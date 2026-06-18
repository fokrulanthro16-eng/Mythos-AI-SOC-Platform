# Mythos — Final Release Checklist

Track status: `[ ]` pending · `[x]` complete · `[-]` N/A or deferred

---

## 1. Code Quality

- [ ] All 24 test files pass: `pytest tests/ -v --tb=short`
- [ ] No import errors on fresh virtualenv: `pip install -r requirements.txt && python -c "import dashboard.app"`
- [ ] `reportlab` listed in requirements or clearly called out as optional
- [ ] No hardcoded secrets, tokens, or passwords in any committed file
- [ ] `.env` is in `.gitignore`; `.env.example` is committed
- [ ] `__pycache__` / `*.pyc` / `.pytest_cache` / `.venv` all in `.gitignore`
- [ ] No `print()` debugging statements left in production code paths
- [ ] All `TODO` / `FIXME` comments resolved or converted to GitHub Issues

---

## 2. Documentation

- [ ] `README.md` — complete rewrite with architecture diagram, feature matrix, quick start ✅
- [ ] `DEPLOYMENT.md` — local dev, Docker Compose, env vars, production checklist ✅
- [ ] `PROJECT_OVERVIEW.md` — technical summary, stack, extension points ✅
- [ ] `DEMO_SCRIPT.md` — 3-minute demo video script with timing marks ✅
- [ ] `RELEASE_CHECKLIST.md` — this file ✅
- [ ] Architecture Mermaid diagram renders correctly in GitHub markdown preview
- [ ] All internal links in README point to valid headings
- [ ] `requirements.txt` reflects all actual runtime dependencies

---

## 3. Data & Seed Files

- [ ] `data/sample_incidents.json` — 50 incidents, all with valid 2026 timestamps
- [ ] `data/threat_profiles.json` — 23 actor profiles, including FIN7 and APT41
- [ ] `data/campaigns.json` — 22 campaigns, including CAMP-FIN7-2026 and CAMP-APT41-2026
- [ ] `data/mitre_attack.json` — present and parseable by `AttackEngine`
- [ ] `logs/case_store.json` — reset to `{"cases": []}` so seed data loads fresh
- [ ] `logs/workbench_store.json` — reset to empty structure so seed data loads fresh
- [ ] `logs/attribution_log.jsonl` — either committed as sample data or excluded via `.gitignore`
- [ ] `reports/` directory exists (`.gitkeep` committed)

---

## 4. Dashboard

- [ ] All 11 pages load without errors on a clean start
- [ ] Page 1 — PDF generator produces a valid PDF for at least one incident
- [ ] Page 6 — Case detail PDF button works on a seeded case
- [ ] Page 8 — Report tab generates PDF from assignment record
- [ ] Page 10 — Executive Dashboard shows non-zero MTTR and MTTD
- [ ] Page 11 — All 6 featured actors appear in the KPI header row
- [ ] Page 11 — Actor Comparison radar chart renders with ≥2 actors
- [ ] All Plotly charts render without console errors
- [ ] Sidebar filters work on all pages that have them
- [ ] `st.cache_data` TTLs are set on all expensive data loads
- [ ] No `st.stop()` called unconditionally (only inside guard conditions)

---

## 5. API

- [ ] `GET /health` returns `{"status": "ok"}` with no auth
- [ ] `POST /auth/login` with valid credentials returns token pair
- [ ] `POST /auth/login` with invalid credentials returns 401
- [ ] `GET /incidents` without token returns 401
- [ ] `GET /incidents` with VIEWER token returns 200
- [ ] `DELETE /incidents/{id}` with ANALYST token returns 403
- [ ] Multi-tenant isolation: user from tenant A cannot read tenant B's incidents
- [ ] Swagger UI at `/docs` loads and all endpoints are documented
- [ ] `GET /metrics` returns Prometheus-format text

---

## 6. Testing

- [ ] All 588 tests pass on Python 3.11
- [ ] All 588 tests pass on Python 3.12 (if applicable)
- [ ] No test relies on a specific port or running external service
- [ ] No test writes to `logs/` (all file I/O uses `tmp_path` or `monkeypatch`)
- [ ] Test suite runs in under 60 seconds on a modern laptop
- [ ] `conftest.py` sets up clean async DB session for all API tests
- [ ] `asyncio_mode = "auto"` is set in `pytest.ini` or `pyproject.toml`

---

## 7. Security

- [ ] JWT secret key is not hardcoded — must come from env
- [ ] Passwords are hashed with bcrypt (min cost factor 12)
- [ ] All SQL queries use parameterised statements (no string formatting into queries)
- [ ] `CORS_ORIGINS` is configurable — not hardcoded to `"*"` in production config
- [ ] Refresh token blacklist checked on every `/auth/refresh` call
- [ ] `audit.jsonl` captures CREATE/UPDATE/DELETE for incidents and cases
- [ ] File upload endpoints (ingest) validate content type and size
- [ ] No sensitive data (passwords, tokens) appears in any log output

---

## 8. Repository

- [ ] Default branch is `main`
- [ ] `LICENSE` file present (choose: MIT / Apache-2.0 / proprietary)
- [ ] Repository description set on GitHub: "AI-powered multi-agent SOC incident orchestration platform"
- [ ] Topics set: `python`, `security`, `fastapi`, `streamlit`, `mitre-attack`, `soc`, `incident-response`
- [ ] At least one GitHub Actions workflow (CI) runs `pytest` on push to `main`
- [ ] `.github/ISSUE_TEMPLATE` set up (optional but recommended)
- [ ] `CONTRIBUTING.md` or contributing section in README (optional)

---

## 9. CI/CD (if applicable)

- [ ] `ci.yml` — runs `pytest tests/ -v` on every push and PR
- [ ] `ci.yml` — uses SQLite (no Postgres service required)
- [ ] `cd.yml` — builds Docker image, pushes to registry, deploys on merge to `main`
- [ ] Docker image builds successfully: `docker build -t mythos/api .`
- [ ] `docker-compose.yml` health checks pass within 30 seconds

---

## 10. Final Pre-Release Verification

- [ ] Record and review the 3-minute demo video against `DEMO_SCRIPT.md`
- [ ] README architecture diagram renders correctly at github.com/your-org/mythos
- [ ] Clone the repository fresh into a new directory and follow Quick Start — it works
- [ ] Run `pytest tests/ -q` from the fresh clone — all 588 pass
- [ ] Tag the release: `git tag v1.0.0 && git push origin v1.0.0`
- [ ] Create GitHub Release with changelog summary

---

## Release Sign-Off

| Area | Reviewer | Status | Date |
|---|---|---|---|
| Code quality & tests | | | |
| Documentation | | | |
| Security review | | | |
| Demo video | | | |
| Final merge to main | | | |

---

## Post-Release

- [ ] Update MEMORY.md / project notes with release tag and date
- [ ] Open Phase 8 planning issue on GitHub
- [ ] Archive `RELEASE_CHECKLIST.md` state at tag in git history
