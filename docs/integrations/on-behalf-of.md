# On-Behalf-Of Delegation (RFC 8693)

> **Status:** v0.43+. Off-by-default per OAuth client. Opt-in via
> `gbrain auth allow-exchange`. Pre-v117 brains must run
> `gbrain apply-migrations` before any of this works.

GBrain implements [RFC 8693 OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
so a *delegator* OAuth client can mint short-lived access tokens scoped to a
specific end-user (a *subject*) without holding that user's credentials.
This is the canonical multi-tenant pattern used by Microsoft Entra
On-Behalf-Of, AWS IAM session policies, Keycloak token exchange, and
Solo.io's MCP authorization patterns.

## Why this exists

Without on-behalf-of, a service that fronts N humans (a WhatsApp gateway,
a Slack bot, a custom internal portal) has two bad options:

1. **One OAuth client per human.** Doesn't scale. Onboarding/offboarding
   each user means manual client registration. And it doesn't work when
   the "human" is anonymous-until-verified (WhatsApp message arriving
   from a brand-new sender).

2. **One shared client with all-access scope.** This is the "confused
   deputy" anti-pattern. The MCP server holds god-mode credentials and
   has to enforce per-user filtering in application code. One bug in
   the persona prompt or routing logic and a junior staff member gets
   the CEO's strategy doc.

RFC 8693 splits the difference. The gateway registers ONE delegator
client. When a turn arrives from user `X`, the gateway exchanges its
own credentials for a short-lived token bound to subject `X`. GBrain
enforces RLS using `X`'s sources, not the delegator's.

## The model

| Concept | Lives in | Holds |
|---|---|---|
| **OAuth client** | `oauth_clients` row | Bearer + `source_id` + `federated_read` + `token_exchange_allowed` + `allowed_subjects` |
| **Subject** | `subjects` row | Opaque ID + `source_id` + `allowed_sources` + advisory `role` |
| **Exchanged token** | `oauth_tokens` row with `subject_id` set | Short-lived; effective RLS scope resolved from subject row at verify time |

Three security gates on every exchange:

1. The calling client must have `token_exchange_allowed = TRUE`.
2. The subject ID must be in the client's `allowed_subjects`
   (or the client is a wildcard delegator: `allowed_subjects = ['*']`).
3. The subject row must exist and not be soft-deleted.

## Operator workflow

```bash
# 1. Register your delegator client (e.g., the WhatsApp gateway service).
gbrain auth register-client "hermes-delegator" \
  --scopes "read write" \
  --grant-types "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
# → Client ID:     gbrain_cl_aaaa...
# → Client Secret: gbrain_cs_bbbb...   (save it; shown once)

# 2. Register your end-users as subjects with their effective RLS scope.
gbrain auth subjects add "87449845936164@lid" \
  --name "Harris Hussain" --role super_admin \
  --source general --allowed-sources general,leadership,finance,ceos,super_admin

gbrain auth subjects add "923001234567@lid" \
  --name "Staff Member" --role staff \
  --source general --allowed-sources general

# 3. Authorize the delegator to act on behalf of those subjects.
gbrain auth allow-exchange gbrain_cl_aaaa... \
  --subjects "87449845936164@lid,923001234567@lid"

# OR — wildcard delegator (any subject the brain knows about).
gbrain auth allow-exchange gbrain_cl_aaaa... --subjects "*"

# 4. List + audit.
gbrain auth subjects list
```

To revoke delegation entirely without deleting the client:

```bash
gbrain auth allow-exchange gbrain_cl_aaaa... --revoke
```

## Wire-level flow

The delegator does an OAuth 2.0 Token Exchange (RFC 8693 §2.1) against
`/token`:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=gbrain_cl_aaaa...
&client_secret=gbrain_cs_bbbb...
&subject_token=87449845936164@lid
&subject_token_type=urn:gbrain:params:oauth:token-type:subject-id
&scope=read
```

Response (RFC 8693 §2.2.1):

```json
{
  "access_token": "gbrain_at_cccc...",
  "token_type": "bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "expires_in": 3600,
  "scope": "read"
}
```

The delegator then uses `access_token` for the duration of the turn. No
refresh token is issued — the delegator mints a fresh token per subject
per turn (cache for ~5 min for cost). Caching is the integrator's
responsibility, not the brain's.

When the brain receives a `Bearer gbrain_at_cccc...` on `/mcp`, its
`verifyAccessToken` notes the token's `subject_id`, looks up the
subjects row, and resolves the request's RLS scope from there — not
from the delegator's `oauth_clients` row. The delegator's `client_id`
stays on the audit trail.

## Subject token types

| Type URI | Meaning | Trust model |
|---|---|---|
| `urn:gbrain:params:oauth:token-type:subject-id` | The `subject_token` parameter is the literal opaque subject ID | The delegator asserts the identity; the brain trusts it because the delegator is allow-listed. Best for gateways that themselves authenticate the end-user (WhatsApp number verification, Slack OAuth, SSO). |
| *(future)* `urn:ietf:params:oauth:token-type:jwt` | The `subject_token` parameter is a signed JWT assertion | The brain verifies the signature against a configured key; non-repudiable. Useful when the gateway itself is less trusted than the IdP that signs the assertion. |

## Audit + observability

Every exchanged token carries the delegator's `client_id` AND the
subject's `subject_id`. Both surface in `AuthInfo`:

- `clientId` → "Hermes acting…" (the agent)
- `subjectId` → "…for subject Saad" (the end-user)

This lets `gbrain doctor`, the admin dashboard, and your own MCP logs
trace every operation to a real person, not a shared service account
— the audit standard most enterprise procurement reviews require.

## Migration safety

- **v116** adds `oauth_clients.token_exchange_allowed` and
  `oauth_clients.allowed_subjects`. Both default to off; existing
  clients are unaffected.
- **v117** adds the `subjects` table and `oauth_tokens.subject_id`.
  Pre-v117 brains that haven't run `apply-migrations` get a clear
  error message on the token-exchange path; non-exchange grants
  (`client_credentials`, `authorization_code`, `refresh_token`)
  continue to work unchanged via the same column-probe fallback
  pattern v60 introduced for source_id.

## Wire-level errors

| HTTP | `error` | When |
|---|---|---|
| 401 | `invalid_client` | `client_id`/`client_secret` missing or wrong; client is public (PKCE-only); client has been soft-deleted via `gbrain auth revoke-client` |
| 400 | `invalid_request` | `subject_token` or `subject_token_type` missing; `subject_token_type` is not `urn:gbrain:params:oauth:token-type:subject-id`; `requested_token_type` is set to anything other than `urn:ietf:params:oauth:token-type:access_token` |
| 400 | `invalid_target` | `resource` parameter is not a parseable URI; `resource` contains a fragment (RFC 8707 §2); `audience` parameter is present (use `resource` instead) |
| 400 | `invalid_grant` | client is not opted in to token-exchange (`gbrain auth allow-exchange` not called); subject is not in client's `allowed_subjects`; subject is unknown or soft-deleted; pre-v116 brain (run `apply-migrations`) |
| 400 | `unauthorized_client` | calling client's `grant_types` registration does not include the token-exchange grant. Re-register via `gbrain auth register-client --grant-types "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"` |
| 400 | `unsupported_grant_type` | `grant_type` parameter value is not recognized by gbrain at all (caught by the MCP SDK's auth router downstream of the gbrain handlers) |
| 429 | `too_many_requests` | per-`client_id` rate limit exceeded (600/minute by default) |

> **Server-side logs** — both successful and failed exchanges emit one structured JSON line per request to gbrain's stdout (captured by systemd / docker logs / cloud log aggregator). The audit row includes `client_id`, `subject_id_hash` (SHA-256 prefix; never the raw subject identifier — GDPR / EDPB Guidelines 01/2025), `requested_scope`, `issued_scope`, `resource`, `source_ip`, and `decision` (allow / deny + `error_code` + safe `log_detail`).

Successful response body matches [RFC 8693 §2.2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1):

```json
{
  "access_token": "gbrain_at_<hex>",
  "token_type": "bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "expires_in": 3600,
  "scope": "read"
}
```

`scope` is REQUIRED in the response when narrower than requested (RFC 8693 §2.2.1) and always present here. `refresh_token` is intentionally absent — see "What this is NOT" below.

`error_description` values on the wire are **fixed strings**. Server logs carry the parameterized form (which scope, which subject id), but the wire response never echoes caller input to avoid leaking config or providing oracle behavior for guessing attacks.

## What this is NOT

- **Not** a way to escalate scope. The exchanged token's scope is
  clamped against the delegator's grant (`max(requested) ∩ delegator.scope`).
- **Not** a way for a public PKCE client to delegate. Only confidential
  clients can exchange. The delegator's `client_secret` is the security
  perimeter.
- **Not** a refresh-token grant. Exchanged tokens are short-lived; the
  delegator re-mints on demand. RFC 8693 §2.2.2 explicitly discourages
  refresh tokens for exchange grants — every mint goes through the
  delegation gate so revocation (`gbrain auth subjects remove`) takes
  effect on the very next call.
- **Not** chained delegation. The `actor_token` parameter from RFC 8693
  §2.1 is not accepted. The delegator IS the actor; only one level of
  delegation is supported. A future revision could accept a chain, but
  the audit-trail and revocation model would need to extend — out of
  scope for this implementation.
- **Not** a JWT issuer. `issued_token_type` is always opaque
  `access_token`. There is no `act` claim because there is no JWT —
  the audit trail lives in `oauth_tokens.client_id` (delegator) +
  `oauth_tokens.subject_id` (end-user) and surfaces in `AuthInfo` on
  every verified request.

## See also

- [recipes/whatsapp-gateway.md](../../recipes/whatsapp-gateway.md) — the
  pattern that motivated this feature.
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) — the underlying spec.
- [RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) —
  the scope clamp.
