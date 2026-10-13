# XCOM ERP & CAS Agent Master Index

This document is the root entrypoint and navigation index for AI agents working in the XCOM ERP (Computerized Accounting System) repository. Follow the routing table below to dynamically load specialized domain knowledge on-demand to maintain high accuracy and prevent context saturation.

---

## 1. Always-On Invariant Rules (`.agents/rules/`)

The rules in `.agents/rules/` are **unconditionally active** across all development activities:
- **`WORKFLOW_RULES.md`**: Strict Read-Only Git Policy (never run git commit/push/merge), mandatory artifact planning, and explicit human approval gates.
- **`FASTAPI_ASYNC_STANDARDS.md`**: Non-blocking async I/O handlers, lifespan context managers, explicit HTTP status codes, and clean dependency injection.

---

## 2. Task-to-Document Routing Matrix

Before writing, analyzing, or refactoring code in any specific domain, **read the corresponding document first**:

| Task Domain | Document to Load & Read | Key Technical Focus |
| :--- | :--- | :--- |
| **Agent Persona & Skepticism** | `.agents/persona/ASSISTANT_BEHAVIOR_PATTERN.md` | Researcher, Doubter, and Notifier mindset |
| **BIR / CAS Compliance** | `.agents/bir-compliance/CAS_FUNCTIONAL_RULES.md` | Immutability, sequential series, audit trails, EIS |
| **Service Layer Architecture** | `.agents/architecture/SERVICE_LAYER_ORCHESTRATION.md` | 3-tier boundary, cross-repo orchestration, thin routers |
| **Router Layer Architecture** | `.agents/architecture/ROUTER_LAYER_ORCHISTRATION.md` | Endpoint naming, /api/public vs /api/private, dependencies |
| **SQLAlchemy 2.0 & ORM Models** | `.agents/skills/sqlalchemy/SKILL.md` | `Mapped[...]`, `BaseRepository`, UUIDv7, async queries |
| **Alembic Database Migrations** | `.agents/skills/alembic-migrations/SKILL.md` | `uv run alembic`, post-gen review, **User runs upgrade** |
| **Pydantic v2 & Data Modeling** | `.agents/skills/pydantic/SKILL.md` | Mandatory `Decimal` for currency, camel/Pascal aliases |
| **Redis Caching & State Keys** | `.agents/skills/redis/SKILL.md` | Key namespacing, mandatory TTL, atomic pipelines |
| **Python uv & Project Tooling** | `.agents/skills/uv/SKILL.md` | `uv run`, `uv.lock` maintenance, absolute `src/` imports |
| **Automated Unit & API Tests** | `.agents/quality-assurance/PYTEST_ASYNC_STANDARDS.md` | DB rollback isolation, mocks, edge-case testing |
| **Manual REST Client Testing** | `.agents/quality-assurance/REST_CLIENT_API_SPEC_STANDARDS.md` | Router mirroring in `docs/apis/<domain>_api.http` |
| **Auth & Session Lifecycles** | `.agents/system_flow/**` | Dual JWT rotation, Redis blacklist, HTTP-Only cookies |

---

## 3. Knowledge Directory Structure

All prompt documents are organized by purpose under `.agents/`:
- **`rules/`**: Universal baseline constraints (Always-On).
- **`persona/`**: Behavioral traits and critical risk escalation patterns.
- **`bir-compliance/`**: Philippine BIR statutory CAS & EIS regulations.
- **`architecture/`**: High-level layer boundaries and system orchestration.
- **`skills/`**: Technical runbooks, code snippets, and framework patterns.
- **`quality-assurance/`**: Pytest testing suites and REST client specifications.
- **`system_flow/`**: End-to-end domain lifecycle diagrams and state flows.

---

## 4. Agent Operational Loop

1. **Identify**: Determine the domain and technical scope of the user request.
2. **Consult**: Read the relevant `.agents/` document(s) from the routing matrix above.
3. **Plan & Confirm**: Produce an artifact implementation plan if architectural changes are required.
4. **Execute**: Implement adhering strictly to the documented domain patterns and invariants.

---

## 5. Dynamic Extension Protocol

When adding new prompts or skills to this repository:
1. Place the document in the appropriate `.agents/<category>/` directory.
2. Register a single-line entry in the **Task-to-Document Routing Matrix** above with the file path and core invariant.
3. Keep all individual prompt files focused, technical, and under their respective line limits.
