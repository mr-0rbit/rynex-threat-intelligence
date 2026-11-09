"""Live smoke test: run CISA KEV collector against the real feed into a local dev DB.

Usage: .venv/bin/python scripts/live_smoke.py cisa-kev
"""

import asyncio
import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:////tmp/opencode/rtip_live.db")
os.environ.setdefault("DEBUG", "false")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


async def main() -> None:
    slug = sys.argv[1] if len(sys.argv) > 1 else "cisa-kev"
    from app.core.database import AsyncSessionLocal, engine
    from app.models import Base
    from app.services.ingestion import run_collector

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        result = await run_collector(slug, db, trigger="manual")
        print(f"source={result['source']} received={result['stored']} stored={result['stored']}")
        if result["errors"]:
            print("ERRORS:", result["errors"])

        # Show a few real records as proof of live ingestion
        from sqlalchemy import select

        from sqlalchemy import func, select

        from app.models import Alert, BreachIncident, IOC, Vulnerability

        vulns = (await db.execute(select(Vulnerability).order_by(Vulnerability.kev_date_added.desc()).limit(5))).scalars().all()
        for v in vulns:
            print(f"  VULN  {v.cve_id} sev={v.severity} kev={v.in_kev} {v.title[:60] if v.title else ''}")
        iocs = (await db.execute(select(IOC).limit(5))).scalars().all()
        for i in iocs:
            print(f"  IOC   {i.value[:60]} type={i.type} conf={i.confidence}")
        breaches = (await db.execute(select(BreachIncident).limit(5))).scalars().all()
        for b in breaches:
            print(f"  BREACH {b.organization_name[:40]} actor={b.threat_actor_name} status={b.verification_status}")
        alerts = (await db.execute(select(Alert).limit(5))).scalars().all()
        for a in alerts:
            print(f"  ALERT [{a.severity}] {a.title[:70]} (conf={a.confidence})")
        total_alerts = (await db.execute(select(func.count()).select_from(Alert))).scalar()
        print(f"  total alerts: {total_alerts}")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
