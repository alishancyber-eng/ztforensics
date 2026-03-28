# Contributing to ZTForensics

Thank you for your interest in contributing to ZTForensics! This document provides everything you need to get started with development, understand the codebase conventions, and submit high-quality pull requests.

---

## Development Setup

### Prerequisites

| Tool              | Version     | Install                                     |
|-------------------|-------------|---------------------------------------------|
| Python            | 3.12+       | [python.org](https://python.org)            |
| Docker Engine     | 24.0+       | [docs.docker.com](https://docs.docker.com)  |
| Docker Compose    | v2.20+      | Included with Docker Desktop                |
| Git               | 2.40+       | `apt install git` / `brew install git`      |

### Clone and install

```bash
# Clone the repository
git clone https://github.com/your-org/ztforensics.git
cd ztforensics

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install API Gateway dependencies (includes test deps)
pip install -r api_gateway/requirements.txt

# Install Dashboard dependencies
pip install -r dashboard/requirements.txt
```

### Start infrastructure services (for integration testing)

```bash
# Start only the infrastructure services (no app containers)
docker compose up -d ztf-postgres ztf-minio ztf-opa

# Set local environment variables
cp .env .env.local
source .env.local   # or use direnv
```

### Run the API Gateway locally

```bash
cd api_gateway
uvicorn main:app --reload --port 8000
```

### Run the Dashboard locally

```bash
cd dashboard
flask run --port 5000
```

---

## Project Structure

```
ztforensics/
├── api_gateway/
│   ├── Dockerfile           # API Gateway container image
│   ├── main.py              # FastAPI application, routes, lifespan
│   ├── risk_scoring.py      # RiskScorer – Python-side risk calculation
│   ├── blockchain.py        # BlockchainManager – SHA-256 hash chain
│   ├── database.py          # SQLAlchemy models and session factory
│   ├── storage.py           # StorageManager – MinIO client wrapper
│   └── requirements.txt     # Python dependencies
│
├── dashboard/
│   ├── Dockerfile           # Dashboard container image
│   ├── app.py               # Flask application
│   ├── templates/
│   │   └── index.html       # Jinja2 dashboard template
│   └── requirements.txt
│
├── opa/
│   └── policies/
│       └── opa_policies.rego  # All OPA Rego policies (package ztf.authz)
│
├── tests/
│   ├── conftest.py          # Pytest fixtures (mocks, test client)
│   ├── test_api.py          # Unit tests for API endpoints
│   ├── test_api_integration.py  # Integration tests
│   ├── test_edge_cases.py   # Edge case and boundary tests
│   ├── test_error_handling.py   # Error handling tests
│   └── test_minio_storage.py    # MinIO storage tests
│
├── docker-compose.yml       # Full stack orchestration
├── .env                     # Default environment variables
├── ARCHITECTURE.md          # System architecture documentation
├── API_REFERENCE.md         # API endpoint documentation
├── SECURITY.md              # Security model and risk scoring
├── OPA_POLICIES.md          # OPA policy documentation
├── DEPLOYMENT.md            # Deployment guide
├── TROUBLESHOOTING.md       # Troubleshooting guide
├── CONTRIBUTING.md          # This file
└── README.md                # Project overview
```

---

## Code Style Guidelines

ZTForensics follows **PEP 8** with the following additional conventions:

### Python

- **Type hints**: Required on all function signatures (parameters and return types)
  ```python
  # ✅ Correct
  def calculate_risk(self, request_data: dict[str, Any]) -> float:

  # ❌ Wrong
  def calculate_risk(self, request_data):
  ```

- **Docstrings**: Google-style docstrings on all public classes and functions
  ```python
  def add_block(self, log_entry: dict[str, Any]) -> str:
      """Append a new block containing *log_entry* to the chain.

      Args:
          log_entry: The access log data to embed in the block.

      Returns:
          The SHA-256 hash of the newly created block.
      """
  ```

- **Imports**: Group as stdlib → third-party → local, sorted alphabetically within each group
  ```python
  import hashlib
  import json
  from datetime import datetime

  import httpx
  from fastapi import FastAPI

  from blockchain import BlockchainManager
  ```

- **Constants**: Module-level constants in `UPPER_SNAKE_CASE`; private sets/tuples prefixed with `_`
  ```python
  _SUSPICIOUS_IPS: set[str] = {"10.0.0.1"}
  ```

- **Line length**: 100 characters maximum

- **String quotes**: Double quotes preferred; single quotes acceptable in simple cases

- **f-strings**: Preferred over `.format()` or `%`-formatting

### Rego (OPA policies)

- Each policy factor is separated by a comment header block
- Use `if` / `in` keywords (futures imported at top)
- Keep rule names prefixed: `deny_*` for denial rules, informational rules use descriptive names
- Set/array literals for blocklists, not hardcoded inline

### Comments

Only comment code that needs clarification. Do not add redundant comments that simply restate the code:

```python
# ❌ Redundant
# Calculate the risk score
risk_score = risk_scorer.calculate_risk(...)

# ✅ Useful – explains non-obvious behaviour
# OPA is queried asynchronously; falls back to allow if unreachable
opa_result = await _query_opa(request)
```

---

## Testing Requirements

### Running the test suite

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=api_gateway --cov-report=term-missing

# Run a specific test file
pytest tests/test_api.py -v

# Run a specific test
pytest tests/test_api.py::test_access_allow -v
```

### Coverage requirement

All pull requests must maintain **95%+ line coverage** on the `api_gateway/` package. Coverage is checked automatically in CI.

```bash
pytest tests/ --cov=api_gateway --cov-report=term-missing --cov-fail-under=95
```

### Test categories

| File                       | Purpose                                               |
|----------------------------|-------------------------------------------------------|
| `test_api.py`              | Unit tests for each API endpoint                      |
| `test_api_integration.py`  | End-to-end request flow tests                         |
| `test_edge_cases.py`       | Boundary conditions, empty inputs, large payloads     |
| `test_error_handling.py`   | Error paths, dependency failures, exception handling  |
| `test_minio_storage.py`    | MinIO storage layer tests                             |

### Writing new tests

- Use the fixtures defined in `tests/conftest.py` (test client, mocked DB, mocked OPA)
- Tests must be **deterministic** and **independent** — no shared state between tests
- Mock external dependencies (PostgreSQL, OPA, MinIO) in unit tests
- Use `pytest.mark.asyncio` for async test functions
- Name tests descriptively: `test_<scenario>_<expected_outcome>`

```python
# Example test structure
def test_access_blocked_ip_returns_deny(client, mock_db):
    """Requests from blocked IPs should be denied with risk_score > 0."""
    response = client.post("/access", json={
        "user_id": "alice",
        "resource": "reports",
        "action": "READ",
        "ip_address": "10.0.0.1",  # in SUSPICIOUS_IPS
    })
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "deny"
    assert data["risk_score"] >= 0.3
```

---

## Pull Request Process

### 1. Create a feature branch

```bash
git checkout -b feature/add-jwt-authentication
# or
git checkout -b fix/opa-fallback-default-deny
```

### 2. Make your changes

Follow the code style guidelines above. Ensure all changes are covered by tests.

### 3. Run the full test suite

```bash
pytest tests/ --cov=api_gateway --cov-report=term-missing -v
```

All tests must pass. Coverage must not drop below 95%.

### 4. Check for linting issues

```bash
# Install linting tools if not already installed
pip install flake8 mypy

# PEP 8 compliance
flake8 api_gateway/ dashboard/ tests/ --max-line-length=100

# Type checking
mypy api_gateway/ --ignore-missing-imports
```

### 5. Update documentation

- If you add a new API endpoint, update `API_REFERENCE.md`
- If you add a new OPA rule, update `OPA_POLICIES.md` and `SECURITY.md`
- If you change deployment configuration, update `DEPLOYMENT.md`

### 6. Commit your changes

```bash
git add .
git commit -m "feat: add JWT bearer token authentication

Add JWT validation middleware to the API Gateway. Tokens are validated
against a configurable JWKS endpoint before the request reaches the
OPA policy engine.

- Add JWTMiddleware to main.py
- Add JWT_ISSUER and JWT_AUDIENCE env vars
- Add tests for valid/invalid/expired tokens

Co-authored-by: Your Name <your@email.com>"
```

### 7. Open a pull request

Push your branch and open a PR against `main`. Ensure:
- [ ] All CI checks pass (tests, coverage, linting)
- [ ] PR description explains the change and why it's needed
- [ ] Related issues are linked (`Closes #42`)
- [ ] Documentation is updated

---

## Commit Message Format

Use the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <short description>

<optional body>

<optional footer>
```

### Types

| Type       | When to use                                              |
|------------|----------------------------------------------------------|
| `feat`     | New feature                                              |
| `fix`      | Bug fix                                                  |
| `docs`     | Documentation changes only                               |
| `test`     | Adding or updating tests                                 |
| `refactor` | Code restructuring without behaviour change              |
| `perf`     | Performance improvement                                  |
| `chore`    | Build system, dependency updates, configuration          |
| `security` | Security fix or improvement                              |

### Examples

```
feat(risk-scoring): add device fingerprinting factor

fix(opa): correct time-of-day boundary to use >= 22 not > 22

docs(api): add POST /access metadata field documentation

test(blockchain): add verify_chain tampered block test

security(opa): add VPN detection to deny conditions
```

---

## Reporting Security Issues

**Do not open a public GitHub issue for security vulnerabilities.**

Email security issues to: `security@your-org.com`

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if known)

We aim to acknowledge reports within 48 hours and provide a fix or mitigation plan within 14 days.
