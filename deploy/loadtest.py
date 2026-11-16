#!/usr/bin/env python3
"""
RTIP Load Testing Script
Run against a deployed RTIP instance to validate performance.

Usage:
    python loadtest.py --base-url https://rtip.rynex.tech --users 50 --duration 300
    RTIP_TOKEN=... python loadtest.py --base-url http://localhost:8000 --users 10 --duration 60

Authentication is required: every measured API route is authenticated. Mint an
access token with POST /api/v1/auth/login and pass it via --token or RTIP_TOKEN
so it is not exposed in the process list.

Requires aiohttp (included in the backend's `dev` extra):
    pip install aiohttp
"""

import argparse
import asyncio
import json
import os
import random
import time
from dataclasses import dataclass
from typing import Any

import aiohttp


@dataclass
class LoadTestConfig:
    base_url: str
    users: int
    duration: int
    token: str | None = None
    ramp_up: int = 30
    think_time: float = 1.0


@dataclass
class TestResult:
    endpoint: str
    method: str
    status: int
    latency_ms: float
    success: bool
    error: str | None = None


class RTIPLoadTester:
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.session: aiohttp.ClientSession | None = None
        self.results: list[TestResult] = []
        self.start_time: float = 0

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    async def _request(
        self, method: str, path: str, **kwargs
    ) -> TestResult:
        url = f"{self.config.base_url}{path}"
        start = time.perf_counter()
        try:
            async with self.session.request(
                method, url, headers=self._headers(), **kwargs
            ) as resp:
                await resp.read()
                latency = (time.perf_counter() - start) * 1000
                return TestResult(
                    endpoint=path,
                    method=method,
                    status=resp.status,
                    latency_ms=latency,
                    success=200 <= resp.status < 400,
                )
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return TestResult(
                endpoint=path,
                method=method,
                status=0,
                latency_ms=latency,
                success=False,
                error=str(e),
            )

    # --- Scenario endpoints ---

    async def health_check(self) -> TestResult:
        return await self._request("GET", "/health")

    async def list_alerts(self) -> TestResult:
        return await self._request("GET", "/api/v1/alerts?limit=20&offset=0")

    async def list_vulnerabilities(self) -> TestResult:
        return await self._request("GET", "/api/v1/vulnerabilities?limit=20&offset=0")

    async def list_iocs(self) -> TestResult:
        return await self._request("GET", "/api/v1/iocs?limit=20&offset=0")

    async def list_breaches(self) -> TestResult:
        return await self._request("GET", "/api/v1/breaches?limit=20&offset=0")

    async def list_news(self) -> TestResult:
        return await self._request("GET", "/api/v1/news?limit=20&offset=0")

    async def list_sources(self) -> TestResult:
        return await self._request("GET", "/api/v1/sources")

    async def dashboard_stats(self) -> TestResult:
        return await self._request("GET", "/api/v1/dashboard/charts")

    async def metrics_endpoint(self) -> TestResult:
        return await self._request("GET", "/api/v1/metrics")

    async def search_global(self, query: str) -> TestResult:
        return await self._request("GET", f"/api/v1/search?q={query}&limit=10")

    async def get_investigations(self) -> TestResult:
        return await self._request("GET", "/api/v1/investigations?limit=20")

    async def get_assets(self) -> TestResult:
        return await self._request("GET", "/api/v1/assets?limit=20")

    async def get_watchlists(self) -> TestResult:
        return await self._request("GET", "/api/v1/watchlists")

    async def get_correlations(self) -> TestResult:
        return await self._request("GET", "/api/v1/correlations?limit=20")

    # --- User simulation ---

    async def simulate_user(self, user_id: int):
        """Simulate a single user's session."""
        await asyncio.sleep(random.uniform(0, self.config.ramp_up))

        scenario_weights = {
            "health": 0.05,
            "alerts": 0.15,
            "vulns": 0.10,
            "iocs": 0.10,
            "breaches": 0.10,
            "news": 0.10,
            "sources": 0.05,
            "dashboard": 0.10,
            "metrics": 0.05,
            "search": 0.10,
            "investigations": 0.05,
            "assets": 0.05,
            "correlations": 0.05,
        }

        scenarios = list(scenario_weights.keys())
        weights = list(scenario_weights.values())

        end_time = self.start_time + self.config.duration

        while time.time() < end_time:
            scenario = random.choices(scenarios, weights=weights)[0]

            try:
                if scenario == "health":
                    result = await self.health_check()
                elif scenario == "alerts":
                    result = await self.list_alerts()
                elif scenario == "vulns":
                    result = await self.list_vulnerabilities()
                elif scenario == "iocs":
                    result = await self.list_iocs()
                elif scenario == "breaches":
                    result = await self.list_breaches()
                elif scenario == "news":
                    result = await self.list_news()
                elif scenario == "sources":
                    result = await self.list_sources()
                elif scenario == "dashboard":
                    result = await self.dashboard_stats()
                elif scenario == "metrics":
                    result = await self.metrics_endpoint()
                elif scenario == "search":
                    query = random.choice([
                        "ransomware", "CVE-2024", "phishing",
                        "malware", "vulnerability", "breach"
                    ])
                    result = await self.search_global(query)
                elif scenario == "investigations":
                    result = await self.get_investigations()
                elif scenario == "assets":
                    result = await self.get_assets()
                elif scenario == "correlations":
                    result = await self.get_correlations()
                else:
                    result = await self.health_check()

                self.results.append(result)

            except Exception as e:
                self.results.append(TestResult(
                    endpoint=scenario,
                    method="GET",
                    status=0,
                    latency_ms=0,
                    success=False,
                    error=str(e),
                ))

            await asyncio.sleep(self.config.think_time + random.uniform(-0.5, 0.5))

    async def run(self):
        self.start_time = time.time()
        print(f"[loadtest] Starting with {self.config.users} users for {self.config.duration}s")

        tasks = [
            asyncio.create_task(self.simulate_user(i))
            for i in range(self.config.users)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        print(f"[loadtest] Completed {len(self.results)} requests")
        return self.report()

    def report(self) -> dict[str, Any]:
        if not self.results:
            return {"error": "No results"}

        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]

        latencies = [r.latency_ms for r in successful]
        latencies.sort()

        total_time = time.time() - self.start_time

        def percentile(p: float) -> float:
            if not latencies:
                return 0
            idx = int(len(latencies) * p / 100)
            return latencies[min(idx, len(latencies) - 1)]

        status_codes: dict[int, int] = {}
        for r in self.results:
            status_codes[r.status] = status_codes.get(r.status, 0) + 1

        return {
            "summary": {
                "total_requests": len(self.results),
                "successful": len(successful),
                "failed": len(failed),
                "success_rate": len(successful) / len(self.results) * 100,
                "duration_seconds": total_time,
                "requests_per_second": len(self.results) / total_time if total_time > 0 else 0,
            },
            "latency_ms": {
                "min": min(latencies) if latencies else 0,
                "max": max(latencies) if latencies else 0,
                "mean": sum(latencies) / len(latencies) if latencies else 0,
                "p50": percentile(50),
                "p90": percentile(90),
                "p95": percentile(95),
                "p99": percentile(99),
            },
            "status_codes": status_codes,
            "errors": [r.error for r in failed if r.error][:10],
        }


def main():
    parser = argparse.ArgumentParser(description="RTIP Load Tester")
    parser.add_argument("--base-url", required=True, help="Base URL (e.g. https://rtip.rynex.tech)")
    parser.add_argument("--users", type=int, default=10, help="Concurrent users")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--token", default=os.environ.get("RTIP_TOKEN"),
                        help="JWT access token (or set RTIP_TOKEN)")
    parser.add_argument("--ramp-up", type=int, default=30, help="Ramp-up period in seconds")
    parser.add_argument("--think-time", type=float, default=1.0, help="Think time between requests")
    parser.add_argument("--output", help="Output JSON file for results")
    args = parser.parse_args()

    if not args.token:
        parser.error("--token or RTIP_TOKEN is required; authenticated routes return 401 otherwise")
    if args.users < 1 or args.duration < 1:
        parser.error("--users and --duration must be positive")

    config = LoadTestConfig(
        base_url=args.base_url.rstrip("/"),
        users=args.users,
        duration=args.duration,
        token=args.token,
        ramp_up=args.ramp_up,
        think_time=max(0.0, args.think_time),
    )

    async def run_test():
        async with RTIPLoadTester(config) as tester:
            report = await tester.run()

        print("\n" + "=" * 50)
        print("LOAD TEST REPORT")
        print("=" * 50)
        print(json.dumps(report, indent=2))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"\nResults written to {args.output}")

        # Exit with non-zero if success rate < 95%
        if report.get("summary", {}).get("success_rate", 0) < 95:
            exit(1)

    asyncio.run(run_test())


if __name__ == "__main__":
    main()