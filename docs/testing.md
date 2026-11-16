# Testing

## Backend

```sh
cd backend
pip install -e ".[dev]"
pytest -q
```

Tests use a throwaway SQLite database created in a fresh temporary directory per
run; they never touch `backend/rtip.db` or a real database.

Migration drift is covered by CI and can be checked locally on a throwaway copy:

```sh
cp backend/rtip.db /tmp/rtip-migration-check.db
cd backend
DATABASE_URL=sqlite+aiosqlite:////tmp/rtip-migration-check.db python -m alembic upgrade head
DATABASE_URL=sqlite+aiosqlite:////tmp/rtip-migration-check.db python -m alembic check
```

## Frontend unit tests and build

```sh
cd frontend
npm ci
npm run test:run
npm run build
```

`npm run build` type-checks the project (including the Playwright specs) before
bundling. The production nginx config can be validated without a cluster:

```sh
docker run --rm -v "$PWD/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  --add-host backend:127.0.0.1 nginx:1.30-alpine nginx -t
```

## Container images

CI builds every image (`backend`, `frontend`, and `deploy/backup`) so base-image
or Dockerfile drift cannot reach a release. Reproduce locally, including the
backup toolchain smoke test:

```sh
docker build -t rtip-backend:local backend
docker build -t rtip-frontend:local frontend
docker build -t rtip/backup:local deploy/backup
docker run --rm rtip/backup:local -c 'pg_dump --version && aws --version'
```

## End-to-end tests

Playwright starts both the backend (throwaway SQLite database) and the Vite dev
server. The authenticated suites require a per-run bootstrap admin account; no
credentials are committed:

```sh
cd frontend
npm ci
npx playwright install --with-deps chromium
E2E_EMAIL=e2e-admin@rtip.test \
E2E_PASSWORD='generate-a-per-run-password' \
E2E_DB_PATH=/tmp/rtip-e2e.db \
npx playwright test --project=chromium
```

Set `PLAYWRIGHT_SKIP_BACKEND=1` to run only the frontend server (for example
against an already-running API). CI generates `E2E_EMAIL`/`E2E_PASSWORD` for
each run and passes the same values to the backend bootstrap environment.
