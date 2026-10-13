# REST Client (.http) API Specification Standards

Whenever creating, modifying, or refactoring API endpoints in `src/modules/`, you MUST create or update corresponding REST Client (`.http`) test files under `docs/apis/`. This operates alongside `pytest` tests to enable direct manual verification and living API documentation.

---

## 1. Directory & File Naming Conventions

- **Location**: All `.http` files reside in `docs/apis/`.
- **Mirror Naming**: Every router module (`src/modules/<domain>/<domain>_router.py`) must have a corresponding `docs/apis/<domain>_api.http` file (e.g., `auth_api.http`, `audit_trail_api.http`, `accounting_api.http`).
- **Global / Middleware APIs**: Shared or middleware endpoints belong in `docs/apis/middlewares.http` or `docs/apis/system.http`.

---

## 2. Mandatory File Structure & Environment Variables

Every `.http` request block must strictly utilize standard environment variables and headers:

- **Host URL**: Use `{{host}}` variable (e.g., `http://localhost:8000`).
- **Content Type**: `Content-Type: application/json` on all requests with JSON payloads.
- **Mandatory Custom Headers**: `X-Header: {{secret_header_value}}` (or any required gateway/security headers).
- **Separator**: Delimit distinct requests with `###` and descriptive section headers.

---

## 3. Request Definition Checklist

For every endpoint in the router, the corresponding `.http` block must provide:

1. **Numbered Header Comment**: Sequential number, clear endpoint title, and access level (e.g., `# 1. User Registration (Public Access)` or `# 2. Post Invoice (Private/RBAC)`).
2. **Behavioral Notes**: Brief explanation of the expected response, status code, side-effects, and cookie handling.
3. **Named Requests for Token Chaining**: Use `@name <request_name>` (e.g. `@name login`) for auth requests so downstream requests can reference captured tokens if needed.
4. **Realistic JSON Payloads**: Sample JSON bodies must 100% match the Pydantic request schema (`*Request`), including valid UUIDs, decimal numbers, and enum codes.
5. **Auth & Cookies**: Document whether the endpoint uses HTTP-Only cookies (handled automatically by REST Client jar) or `Authorization: Bearer <token>` headers.

---

## 4. Standard Reference Template

```http
###
# 1. Create Sales Invoice (Private - Accounting Role)
# Creates a new sales invoice. Returns HTTP 201 Created.
# @name createInvoice
POST {{host}}/api/private/accounting/invoices
Content-Type: application/json
X-Header: {{secret_header_value}}
Authorization: Bearer {{login.response.body.authTokenPayload.accessToken}}

{
    "customerId": "018f3a21-9876-7cb1-a012-3456789abcde",
    "invoiceDate": "2026-10-08T09:00:00Z",
    "items": [
        {
            "description": "Consulting Services",
            "quantity": 1,
            "unitCost": "5000.00",
            "taxType": "VATABLE"
        }
    ]
}
```

---

## 5. Maintenance Invariant

> [!IMPORTANT]
> Whenever an endpoint's path, schema, query params, or auth rules change in Python code, the corresponding `.http` specification in `docs/apis/` MUST be updated in the same task. Never leave orphaned or outdated REST client files.
