# Mythos — Deployment Guide

This guide covers local development, Docker Compose (full stack), and production deployment.

---

## Contents

- [Local Development](#local-development)
- [Docker Compose](#docker-compose)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Production Checklist](#production-checklist)
- [Service URLs](#service-urls)
- [Monitoring](#monitoring)
- [Scaling Notes](#scaling-notes)

---

## Local Development

### Requirements

| Tool | Minimum Version |
|---|---|
| Python | 3.11+ |
| pip | 23+ |
| Git | any |
| PostgreSQL | 14+ (optional — SQLite used if not set) |
| Redis | 7+ (optional — in-memory fallback if not set) |

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/mythos.git
cd mythos

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# Optional: PDF report generation
pip install reportlab
```

### Configure environment

```bash
cp .env.example .env
# Edit .env — for local dev, defaults work without Postgres/Redis
```

### Run the agent pipeline

```bash
# Processes all incidents in data/sample_incidents.json
# Writes results to logs/attribution_log.jsonl and logs/attribution_log.csv
python core/orchestrator.py
```

### Launch the Streamlit dashboard

```bash
python -m streamlit run dashboard/app.py
# Opens at http://localhost:8501
```

### Launch the FastAPI REST API

```bash
uvicorn api.main:app --reload --port 8000
# Swagger UI at http://localhost:8000/docs
# ReDoc at http://localhost:8000/redoc
```

### Run all tests

```bash
pytest tests/ -v --tb=short

# Run a specific test file
pytest tests/test_executive_store.py -v

# Run with coverage
pip install pytest-cov
pytest tests/ --cov=. --cov-report=term-missing
```

---

## Docker Compose

The `docker-compose.yml` brings up the full stack in one command.

### Services

| Service | Image | Port |
|---|---|---|
| `api` | `mythos/api:latest` | 8000 |
| `dashboard` | `mythos/dashboard:latest` | 8501 |
| `db` | `postgres:16-alpine` | 5432 |
| `redis` | `redis:7-alpine` | 6379 |
| `prometheus` | `prom/prometheus:latest` | 9090 |
| `grafana` | `grafana/grafana:latest` | 3000 |
| `migrate` | one-shot Alembic runner | — |

### Start the full stack

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env — set JWT_SECRET_KEY and strong DB passwords

# Build images and start all services
docker compose up -d --build

# Run database migrations (first time or after schema changes)
docker compose run --rm migrate

# Seed initial data
docker compose exec api python -c "
from api.db.database import init_db
import asyncio
asyncio.run(init_db())
"

# Verify services are healthy
docker compose ps
curl http://localhost:8000/health
```

### Useful commands

```bash
# View logs for a service
docker compose logs -f api

# Restart a single service
docker compose restart dashboard

# Stop everything (preserves volumes)
docker compose down

# Stop everything AND delete volumes (full reset)
docker compose down -v

# Open a shell in the API container
docker compose exec api bash

# Run a migration manually
docker compose exec api alembic upgrade head

# Run tests inside the container
docker compose exec api pytest tests/ -v
```

---

## Environment Variables

All variables are read from `.env` (or from shell environment for CI).

### Required for production

| Variable | Description | Example |
|---|---|---|
| `JWT_SECRET_KEY` | HS256 signing key (min 256 bits) | `openssl rand -hex 32` |
| `DATABASE_URL` | Async PostgreSQL connection string | `postgresql+asyncpg://mythos:pass@db:5432/mythos` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379/0` |

### Optional / defaults shown

| Variable | Default | Description |
|---|---|---|
| `MYTHOS_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `CONFIDENCE_THRESHOLD` | `0.75` | Minimum confidence to mark as attributed |
| `RISK_CRITICAL_THRESHOLD` | `0.80` | Risk score threshold for CRITICAL label |
| `SQL_ECHO` | `false` | Log SQL queries (set `true` for debugging only) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | JWT access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | JWT refresh token TTL |
| `CORS_ORIGINS` | `*` | Comma-separated allowed CORS origins |
| `API_HOST` | `0.0.0.0` | Bind address for uvicorn |
| `API_PORT` | `8000` | Port for uvicorn |
| `STREAMLIT_SERVER_PORT` | `8501` | Streamlit port |

### Generating a secure JWT secret

```bash
openssl rand -hex 32
# or
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Database Setup

### Local SQLite (development, no config needed)

When `DATABASE_URL` is not set, the application automatically uses SQLite at `./mythos_local.db`. No migration is required — `init_db()` creates all tables on startup.

### PostgreSQL (production)

```bash
# Create database and user
psql -U postgres <<SQL
CREATE USER mythos WITH PASSWORD 'strongpassword';
CREATE DATABASE mythos OWNER mythos;
GRANT ALL PRIVILEGES ON DATABASE mythos TO mythos;
SQL

# Set DATABASE_URL in .env
DATABASE_URL=postgresql+asyncpg://mythos:strongpassword@localhost:5432/mythos

# Run Alembic migrations
alembic upgrade head
```

### Alembic migration commands

```bash
# Apply all pending migrations
alembic upgrade head

# Roll back one step
alembic downgrade -1

# Show current revision
alembic current

# Show migration history
alembic history

# Auto-generate a new migration from model changes
alembic revision --autogenerate -m "add new_column to incidents"

# Review generated migration before applying
cat alembic/versions/<timestamp>_add_new_column_to_incidents.py
alembic upgrade head
```

---

## Production Checklist

### Security

- [ ] Set `JWT_SECRET_KEY` to a cryptographically random 256-bit value
- [ ] Use strong, unique passwords for PostgreSQL and Redis
- [ ] Configure TLS termination at your reverse proxy (nginx / Traefik / Caddy)
- [ ] Set `CORS_ORIGINS` to your specific frontend domain(s), not `*`
- [ ] Set `SQL_ECHO=false`
- [ ] Rotate the default Grafana admin password (`admin/admin`) immediately
- [ ] Enable firewall rules — expose only ports 80 and 443 externally
- [ ] Enable PostgreSQL SSL (`sslmode=require` in `DATABASE_URL`)
- [ ] Configure Redis authentication with `requirepass` in `redis.conf`
- [ ] Review and restrict file permissions on `.env` (`chmod 600 .env`)

### Reliability

- [ ] Run `alembic upgrade head` as part of your deploy script (before starting API)
- [ ] Configure PostgreSQL connection pool limits (`pool_size`, `max_overflow` in `database.py`)
- [ ] Set up Redis persistence (AOF or RDB) for JWT blacklist durability
- [ ] Configure log rotation for `logs/*.jsonl` files
- [ ] Set up health-check probes on `/health` for your container orchestrator
- [ ] Configure Prometheus retention period and alert rules for critical metrics
- [ ] Set up automated database backups (pg_dump schedule)

### Monitoring

- [ ] Verify Prometheus is scraping `http://api:8000/metrics`
- [ ] Import `monitoring/grafana/dashboards/mythos_overview.json` into Grafana
- [ ] Configure alert rules for `mythos_auth_failures_total` and pipeline error rates
- [ ] Set up Grafana email/Slack notifications for critical alerts

### Performance

- [ ] Set `workers` in uvicorn to match CPU cores: `uvicorn api.main:app --workers 4`
- [ ] Enable HTTP/2 at the reverse proxy layer
- [ ] Configure CDN caching for static Streamlit assets if exposed publicly
- [ ] Review and tune `@st.cache_data(ttl=30)` TTLs on hot dashboard paths

---

## Service URLs

| Service | Local URL | Docker URL |
|---|---|---|
| Streamlit Dashboard | http://localhost:8501 | http://localhost:8501 |
| FastAPI (Swagger) | http://localhost:8000/docs | http://localhost:8000/docs |
| FastAPI (ReDoc) | http://localhost:8000/redoc | http://localhost:8000/redoc |
| FastAPI health | http://localhost:8000/health | http://localhost:8000/health |
| Prometheus | — | http://localhost:9090 |
| Grafana | — | http://localhost:3000 (admin/admin) |
| PostgreSQL | localhost:5432 | db:5432 (internal) |
| Redis | localhost:6379 | redis:6379 (internal) |

---

## Monitoring

### Prometheus metrics (available at `/metrics`)

| Metric | Type | Description |
|---|---|---|
| `mythos_http_requests_total` | Counter | All requests by method / path / status |
| `mythos_http_request_duration_seconds` | Histogram | Latency per endpoint |
| `mythos_http_requests_in_flight` | Gauge | Concurrent request count |
| `mythos_incidents_created_total` | Counter | New incidents by tenant / severity |
| `mythos_pipeline_runs_total` | Counter | Pipeline executions by outcome |
| `mythos_pipeline_duration_seconds` | Histogram | Pipeline latency by threat name |
| `mythos_auth_logins_total` | Counter | Successful logins by tenant |
| `mythos_auth_failures_total` | Counter | Auth failures by reason |
| `mythos_cases_created_total` | Counter | New cases by tenant / priority |
| `mythos_active_cases` | Gauge | Open cases by tenant |

### Grafana dashboard panels

The pre-provisioned `monitoring/grafana/dashboards/mythos_overview.json` includes 10 panels:

1. API Request Rate
2. API Error Rate
3. P95 Request Latency
4. Pipeline Execution Duration
5. Total Incidents (stat)
6. Active Cases (stat)
7. Auth Failures (stat)
8. Pipeline Runs by Outcome (pie)
9. Incidents by Severity (bar)
10. Auth Failures Over Time

### Audit log

All write operations append a structured entry to `logs/audit.jsonl`:

```json
{
  "timestamp": "2026-06-17T14:22:00Z",
  "action": "CREATE_INCIDENT",
  "resource_type": "incident",
  "resource_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "...",
  "tenant_id": "...",
  "outcome": "SUCCESS",
  "ip": "10.0.0.1",
  "detail": {"threat_name": "LOCKBIT4-RANSOMWARE", "severity": "CRITICAL"}
}
```

---

## Scaling Notes

**Streamlit** is single-process per instance. For horizontal scaling, run multiple instances behind a load balancer with sticky sessions (Streamlit requires WebSocket affinity). Each instance reads from the same shared `logs/` directory or PostgreSQL.

**FastAPI** scales horizontally with `--workers N`. All state is in PostgreSQL/Redis, so instances are stateless. Use a load balancer (nginx, HAProxy) in front.

**PostgreSQL** — for high write volumes, consider read replicas for dashboard queries. Connection pooling via PgBouncer is recommended above 100 concurrent connections.

**Redis** — in-memory JWT blacklist is cleared on restart. Use Redis Cluster or Sentinel for high availability. Current blacklist TTL matches refresh token expiry (7 days).
