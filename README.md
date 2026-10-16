# Atlas

**The extensible backend platform for AI applications and autonomous agents.**

[![Python](https://img.shields.io/badge/Python-3.14%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-red.svg)](https://www.sqlalchemy.org/)
[![Alembic](https://img.shields.io/badge/Alembic-Migrations-orange.svg)](https://alembic.sqlalchemy.org/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/Tests-27%20Passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What Atlas is

Atlas is an open-source backend engine designed specifically for applications that run artificial intelligence workloads.

In a tutorial or prototype, building an AI app looks as simple as making an API call to an LLM. In production, building an AI product breaks nearly every assumption of traditional web architecture:

- **Long inference latencies**: Large language models generate responses autoregressively over seconds or minutes. Holding synchronous threads blocks server workers and triggers cascading gateway timeouts. Atlas uses an asynchronous ASGI event loop and streaming primitives (Server-Sent Events and WebSockets) to support thousands of concurrent model connections.
- **Heavy document ingestion**: Parsing PDFs, chunking text, and generating high-dimensional vector embeddings cannot run in the synchronous request-response loop without exhausting memory or causing client disconnects. Atlas decouples heavy processing into background task queues.
- **Multi-tenant data leaks**: Semantic search finds text across an entire vector space by mathematical similarity. Without strict tenant boundaries, a query from User A can retrieve private embeddings belonging to User B. Atlas enforces project-level data isolation.
- **Runaway API costs**: Autonomous agent loops and unbounded client queries can consume millions of tokens in minutes. Atlas includes centralized reverse proxying, programmatic API keys, token accounting, and hard spend caps.

Atlas provides the foundational platform to solve these problems out of the box: user identity, token authentication, role-based access control, project multi-tenancy, and version-controlled database migrations.

---

## Platform capabilities

### Identity, authentication, and access control
- **OAuth2 and signed JWTs**: Standards-compliant bearer token exchange (`POST /auth/login`) with HMAC-SHA256 signatures, supporting login with either username or email.
- **Argon2id password security**: Passwords are protected using memory-hard Argon2id hashing (64 MB RAM, 3 iterations) and constant-time verification, preventing GPU brute-force and timing attacks.
- **Role-Based (RBAC) and Ownership (ABAC) Access Control**: Composable dependencies (`get_current_active_user`, `get_current_active_superuser`) and strict resource ownership checks eliminate OWASP API Top 10 Broken Object Level Authorization (BOLA/IDOR) vulnerabilities.
- **NIST SP 800-63B validation**: Password rules enforce 8 to 128 character bounds to block algorithmic complexity DoS attacks, validate RFC 5322 email syntax, and reject passwords containing the user's handle or email prefix.

### Multi-tenant workspaces *(Phase 2)*
- Project-level boundaries ensuring users, documents, vector stores, and API keys are strictly partitioned.
- Team collaboration with granular member access roles.

### Asynchronous AI gateway and streaming *(Phase 4)*
- Unified client adapters for major model providers (OpenAI, Anthropic, Gemini, local models).
- Native token-by-token streaming over Server-Sent Events (SSE) and WebSockets with low Time-To-First-Token (TTFT).

### Document ingestion and semantic retrieval *(Phases 3 & 5)*
- Asynchronous ingestion pipelines for PDFs, Markdown, and plain text.
- Chunking, embedding generation, and metadata-filtered vector persistence (pgvector).

### Programmatic API keys and usage metering *(Phase 6)*
- Cryptographically hashed API keys (`atlas_live_...`) for machine-to-machine integrations.
- Append-only token usage ledger tracking prompt tokens, completion tokens, and real-time spend caps.

---

## Quickstart

### Prerequisites
- Python 3.14 or newer
- [uv](https://docs.astral.sh/uv/) package manager

```bash
# 1. Clone the repository
git clone https://github.com/hemang1404/Atlas.git
cd Atlas

# 2. Install dependencies
uv sync

# 3. Configure environment
cp .env.example .env

# 4. Run database migrations
uv run alembic upgrade head

# 5. Start the development server
uv run uvicorn main:app --reload
```

Once running, explore the interactive OpenAPI interface at **[http://localhost:8000/docs](http://localhost:8000/docs)**.

---

## Running tests

Run the complete integration and unit test suite:

```bash
uv run pytest -v
```

Tests run in-memory using SQLite connection pooling (`StaticPool`) and execute in under two seconds.

---

## Tech stack

- **Framework**: FastAPI (ASGI)
- **Runtime**: Python 3.14+ managed with `uv`
- **Database**: SQLite (development) / PostgreSQL (production) via SQLAlchemy 2.0
- **Migrations**: Alembic
- **Validation**: Pydantic v2
- **Security**: Argon2id (`pwdlib`), signed JWTs (`pyjwt`)
- **Testing**: Pytest with `httpx`

---

## Roadmap

- [x] **Phase 1: Foundation & Identity** (SQLAlchemy 2.0, Alembic, Argon2id, OAuth2/JWT, RBAC & Ownership security)
- [ ] **Phase 2: Tenancy & Scoped API Keys** (Project workspaces, tenant isolation, hashed platform keys)
- [ ] **Phase 3: Ingestion & Object Storage** (File uploads, document extraction, chunking)
- [ ] **Phase 4: AI Gateway & Streaming** (Unified model adapters, SSE/WebSocket token streaming)
- [ ] **Phase 5: Semantic Retrieval** (pgvector integration, tenant-scoped RAG search)
- [ ] **Phase 6: Usage Metering** (Token ledger, rate limits, budget spend caps)

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
