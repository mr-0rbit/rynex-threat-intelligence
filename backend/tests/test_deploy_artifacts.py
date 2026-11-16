"""Regression checks for deployment YAML and monitoring/metrics contracts."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def _load_yaml(path: Path) -> list[object]:
    return list(yaml.safe_load_all(path.read_text()))


def test_deployment_and_monitoring_yaml_parse():
    paths = [
        ROOT / "deploy/k8s/backup-cronjob.yaml",
        ROOT / "deploy/k8s/kustomization.yaml",
        ROOT / "deploy/monitoring/workloads.yaml",
        ROOT / "deploy/monitoring/kustomization.yaml",
        ROOT / "deploy/monitoring/alertmanager.yaml",
        ROOT / "deploy/monitoring/alerts.yaml",
        ROOT / "deploy/monitoring/prometheus.yaml",
        ROOT / "deploy/monitoring/servicemonitor.yaml",
    ]

    for path in paths:
        parsed = _load_yaml(path)
        assert parsed and all(document is not None for document in parsed), path


def test_alert_rules_only_reference_metrics_exposed_by_backend():
    source = (ROOT / "backend/app/api/v1/metrics.py").read_text()
    exposed = set(re.findall(r'"(rtip_[a-z0-9_]+)"', source))
    rule_groups = yaml.safe_load((ROOT / "deploy/monitoring/alerts.yaml").read_text())
    expressions = [
        str(rule.get("expr", ""))
        for group in rule_groups["groups"]
        for rule in group["rules"]
    ]
    referenced = {
        metric
        for expression in expressions
        for metric in re.findall(r"\b(rtip_[a-z0-9_]+)\b", expression)
    }

    assert referenced <= exposed


def test_monitoring_scrape_and_alert_credentials_are_secret_file_based():
    prometheus = yaml.safe_load((ROOT / "deploy/monitoring/prometheus.yaml").read_text())
    scrape = next(
        job for job in prometheus["scrape_configs"] if job["job_name"] == "rtip-backend"
    )
    assert scrape["bearer_token_file"] == "/etc/prometheus/secrets/metrics-api-key"

    alertmanager = yaml.safe_load(
        (ROOT / "deploy/monitoring/alertmanager.yaml").read_text()
    )
    assert alertmanager["global"]["smtp_auth_password_file"] == (
        "/etc/alertmanager/secrets/smtp-password"
    )


def test_monitoring_kustomization_sources_exist():
    directory = ROOT / "deploy/monitoring"
    kustomization = yaml.safe_load((directory / "kustomization.yaml").read_text())

    for resource in kustomization["resources"]:
        assert (directory / resource).is_file(), resource

    for generator in kustomization["configMapGenerator"]:
        for entry in generator["files"]:
            source = entry.split("=", 1)[-1]
            assert (directory / source).is_file(), source
            # ConfigMap keys cannot contain a slash.
            key = entry.split("=", 1)[0] if "=" in entry else source
            assert "/" not in key, key


def test_application_images_are_pinned_or_transformed_by_kustomize():
    base = ROOT / "deploy/k8s"
    kustomization = yaml.safe_load((base / "kustomization.yaml").read_text())
    transformed = {entry["name"] for entry in kustomization.get("images", [])}

    workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
    checked = 0
    for path in sorted(base.glob("*.yaml")):
        for document in _load_yaml(path):
            if not isinstance(document, dict) or document.get("kind") not in workload_kinds:
                continue
            if document["kind"] == "CronJob":
                pod_spec = document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
            else:
                pod_spec = document["spec"]["template"]["spec"]
            containers = pod_spec.get("initContainers", []) + pod_spec.get("containers", [])
            for container in containers:
                image = container["image"]
                repository, _, tag = image.rpartition(":")
                # A colon inside a registry host:port is not a tag separator.
                if "/" in tag:
                    repository, tag = image, ""
                if tag in {"", "latest"}:
                    assert repository in transformed, (
                        f"{path.name}:{container['name']} uses mutable image {image} "
                        "and has no kustomization images override"
                    )
                checked += 1
    assert checked >= 5


def test_container_base_images_are_pinned_and_ci_aligned():
    frontend = (ROOT / "frontend/Dockerfile").read_text()
    nginx_tag = re.search(r"^FROM nginx:(\S+)", frontend, re.M).group(1)
    assert nginx_tag != "latest"
    # CI validates the same nginx release the image ships.
    assert f"nginx:{nginx_tag}" in (ROOT / ".github/workflows/ci.yml").read_text()

    for dockerfile in ROOT.rglob("Dockerfile"):
        if "node_modules" in dockerfile.parts:
            continue
        for image in re.findall(r"^FROM (\S+)", dockerfile.read_text(), re.M):
            assert not image.endswith(":latest"), dockerfile


def test_backend_image_installs_the_application_package():
    dockerfile = (ROOT / "backend/Dockerfile").read_text()
    install = re.search(r"^RUN pip install .*$", dockerfile, re.M)
    assert install
    # The wheel is only non-empty when the package exists in the build context.
    assert dockerfile.index("COPY app ./app") < install.start()


def test_backup_image_uses_glibc_postgres_and_aws_cli_v2():
    dockerfile = (ROOT / "deploy/backup/Dockerfile").read_text()
    assert "FROM postgres:17" in dockerfile
    assert re.search(r"^FROM amazon/aws-cli:\d", dockerfile, re.M)
    # Alpine's aws-cli package is the EOL v1 line and cannot run there.
    assert "apk add" not in dockerfile


def test_backup_cronjob_matches_documented_rpo_and_needs_no_secret_rbac():
    documents = _load_yaml(ROOT / "deploy/k8s/backup-cronjob.yaml")
    cronjob = next(doc for doc in documents if doc["kind"] == "CronJob")
    assert cronjob["spec"]["schedule"] == "0 * * * *"

    container = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    # The stock postgres image has no AWS CLI, so the job must use the
    # purpose-built backup image and bash (not ash) for pipefail.
    assert container["image"].endswith("rtip/backup:1.0.0")
    assert container["command"][:2] == ["/bin/bash", "-c"]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    env_names = {entry["name"] for entry in container["env"]}
    assert {"DATABASE_URL", "S3_BUCKET", "AWS_ACCESS_KEY_ID"} <= env_names

    # Secret values reach the pod through secretKeyRef (resolved by kubelet);
    # the ServiceAccount never needs permission to read the Kubernetes API.
    for document in documents:
        if document["kind"] == "Role":
            resources = {
                resource
                for rule in document.get("rules", [])
                for resource in rule.get("resources", [])
            }
            assert "secrets" not in resources


def test_monitoring_workloads_mount_credentials_and_use_immutable_tags():
    documents = _load_yaml(ROOT / "deploy/monitoring/workloads.yaml")
    deployments = {
        doc["metadata"]["name"]: doc
        for doc in documents
        if doc.get("kind") == "Deployment"
    }

    for name, deployment in deployments.items():
        spec = deployment["spec"]["template"]["spec"]
        assert spec["automountServiceAccountToken"] is False, name
        container = spec["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        # Pin monitoring images by explicit version, never :latest.
        assert not container["image"].endswith(":latest"), name

    prometheus = deployments["prometheus"]["spec"]["template"]["spec"]
    mounts = {mount["name"] for mount in prometheus["containers"][0]["volumeMounts"]}
    assert "metrics-credentials" in mounts

    alertmanager = deployments["alertmanager"]["spec"]["template"]["spec"]
    mounts = {mount["name"] for mount in alertmanager["containers"][0]["volumeMounts"]}
    assert "smtp-credentials" in mounts
