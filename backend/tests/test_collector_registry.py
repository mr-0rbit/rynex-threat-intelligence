from app.collectors.registry import connector_requires_api_key, has_configured_api_key


def test_keyed_connectors_report_key_presence_without_exposing_value(monkeypatch) -> None:
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    assert not has_configured_api_key("urlhaus")

    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-only-placeholder")
    assert has_configured_api_key("urlhaus")


def test_unknown_or_keyless_connectors_have_no_configured_api_key() -> None:
    assert not has_configured_api_key("not-a-connector")
    assert not has_configured_api_key("blocklist-de")


def test_only_connectors_that_require_credentials_are_marked_required() -> None:
    assert connector_requires_api_key("urlhaus")
    assert connector_requires_api_key("threatfox")
    assert not connector_requires_api_key("ransomware-live")
    assert not connector_requires_api_key("darkweb-groups")
    assert not connector_requires_api_key("nvd")
