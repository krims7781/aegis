# Aegis 🛡️
### Low-Latency PII & Token Masking Proxy for LLM APIs

Aegis is an asynchronous security middleware that sits between your application and any LLM API (OpenAI, Anthropic, etc.). It intercepts outgoing payloads, scrubs **Personally Identifiable Information (PII)** and **API secrets** in real-time, forwards the sanitized request upstream, then reconstructs the response — so your application receives coherent replies without ever leaking sensitive data.

```
Client → [Aegis Proxy] → LLM API
           ↓ scrub PII          ↑ reconstruct tokens
           ↓ vault tokens       ↑ restore originals
```

---

## Why Aegis?

Modern LLM integrations routinely pass user-generated text — which may contain emails, phone numbers, credit card numbers, or API keys — directly to third-party AI providers. Aegis eliminates that risk with **zero changes to your application code**.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Aegis Proxy                      │
│                                                     │
│  POST /proxy/chat                                   │
│        │                                            │
│        ▼                                            │
│  ┌─────────────┐    ┌──────────────────────────┐   │
│  │   Scrubber  │    │   Aho-Corasick Engine    │   │
│  │             │───▶│   O(N) multi-pattern     │   │
│  │  Regex Layer│    │   keyword detection      │   │
│  └─────────────┘    └──────────────────────────┘   │
│        │                                            │
│        ▼                                            │
│  ┌─────────────┐                                    │
│  │    Vault    │  SQLite in-memory token store      │
│  │  (bi-dir)   │  original ↔ __TK_XXXXXXXX__       │
│  └─────────────┘                                    │
│        │                                            │
│        ▼                                            │
│  Forward sanitized payload → upstream LLM           │
│  Reconstruct response tokens → return to client     │
└─────────────────────────────────────────────────────┘
```

### Two-Layer Detection

| Layer | Mechanism | Detects |
|-------|-----------|---------|
| **Regex** | Pre-compiled patterns | Emails, phone numbers, credit cards, SSNs, JWTs, AWS keys, GitHub PATs, OpenAI keys, UUIDs, IPs |
| **Aho-Corasick** | Finite automaton, O(N) | Custom keywords: employee names, project codenames, org-specific tokens |

### Bi-Directional Token Vault

When a value is redacted, it's stored in a thread-local SQLite in-memory vault:

```
"john@acme.com"  →  stored  →  __TK_A3F2C1B0__
                  ←  restore ←
```

LLM responses referencing the token are automatically reconstructed before delivery to the client.

---

## Performance

Benchmarked on a 2020 MacBook Pro (M1):

| Input Size | Avg Scrub Time | Redactions |
|------------|---------------|------------|
| 200 chars  | **0.13 ms**   | 2          |
| 2,000 chars| **0.41 ms**   | 8          |
| 20,000 chars| **3.2 ms**  | 40+        |

**Target: sub-8ms for typical LLM payloads** ✓

---

## Quickstart

### 1. Clone & Install

```bash
git clone https://github.com/krims7781/aegis.git
cd aegis
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env: set UPSTREAM_API_KEY to your OpenAI (or compatible) API key
```

### 3. Run

```bash
python main.py
# Server starts at http://localhost:8000
```

### 4. Try it — scrub without an LLM key

```bash
curl -X POST http://localhost:8000/proxy/scrub-only \
  -H "Content-Type: application/json" \
  -d '{"text": "Hi, I am John. Email me at john@acme.com or call 9876543210. My card: 4111-1111-1111-1111"}'
```

Response:
```json
{
  "original": "Hi, I am John. Email me at john@acme.com or call 9876543210. My card: 4111-1111-1111-1111",
  "sanitized": "Hi, I am John. Email me at [EMAIL] or call [PHONE_IN]. My card: [CREDIT_CARD]",
  "redactions": [...],
  "processing_ms": 0.13,
  "regex_matches": 3,
  "ac_matches": 0
}
```

### 5. Full proxy with LLM forwarding

```bash
curl -X POST http://localhost:8000/proxy/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "user", "content": "Summarize this for john@acme.com: our Q3 revenue was $4.2M"}
    ],
    "model": "gpt-3.5-turbo"
  }'
```

---

## Docker

```bash
docker build -t aegis .
docker run -p 8000:8000 -e UPSTREAM_API_KEY=sk-... aegis
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/proxy/chat` | Scrub + forward to LLM + reconstruct response |
| `POST` | `/proxy/scrub-only` | Scrub text only, no LLM forwarding |
| `GET`  | `/proxy/vault/stats` | View stored token count |
| `DELETE` | `/proxy/vault` | Clear all vault mappings |
| `GET`  | `/health` | Service health check |

Interactive docs: `http://localhost:8000/docs` (Swagger UI, auto-generated)

---

## Detected PII Types

| Label | Example |
|-------|---------|
| `EMAIL` | `john@acme.com` |
| `PHONE_IN` | `+91-9876543210` |
| `PHONE_US` | `415-555-0100` |
| `CREDIT_CARD` | `4111-1111-1111-1111` |
| `SSN` | `123-45-6789` |
| `IP_ADDRESS` | `192.168.1.1` |
| `UUID` | `550e8400-e29b-41d4...` |
| `JWT` | `eyJhbGci...` |
| `API_KEY_GEN` | `sk-abc123...` |
| `AWS_KEY` | `AKIAIOSFODNN7EXAMPLE` |
| `GITHUB_PAT` | `ghp_xxxxxxxxxxxx` |
| `OPENAI_KEY` | `sk-` + 48 chars |
| `KEYWORD` | Custom (via Aho-Corasick) |

---

## Project Structure

```
aegis/
├── main.py              # Entry point
├── app.py               # FastAPI app factory
├── core/
│   ├── aho_corasick.py  # AC automaton implementation (from scratch)
│   ├── scrubber.py      # Two-layer PII detection engine
│   └── vault.py         # Bi-directional SQLite token store
├── routes/
│   ├── proxy.py         # Core proxy + scrub endpoints
│   └── health.py        # Health check
├── tests/
│   └── test_core.py     # Unit tests (AC, Scrubber, Vault)
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Tech Stack

- **Python 3.11** · **FastAPI** · **SQLite (in-memory)** · **httpx** (async HTTP)
- Aho-Corasick implemented from scratch — no external string-matching library

---

## License

MIT
