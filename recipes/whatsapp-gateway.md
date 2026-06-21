# Recipe: WhatsApp Gateway → GBrain (per-user RLS)

A WhatsApp number that fronts your team's brain. Different employees
ask different questions, and each one gets answers scoped to what
they're allowed to see — enforced at the SQL layer by GBrain's RLS,
not by the prompt.

This is the canonical use case for [RFC 8693 token-exchange](../docs/integrations/on-behalf-of.md).
A single OAuth client (the gateway) mints a fresh per-user token at
every turn. The brain enforces isolation.

## Architecture

```
┌──────────────┐    WhatsApp message              ┌──────────────┐
│   Saad's     │ ────► from 923354811400@lid ───► │   Gateway    │
│   phone      │                                  │  (Hermes,    │
└──────────────┘                                  │   Slack bot, │
                                                  │   etc.)      │
                                                  └──────┬───────┘
                                                         │
   2. POST /token (grant=token-exchange,                 │
      subject_token=923354811400@lid)                    │
                                                         ▼
                                                  ┌──────────────┐
                                                  │   GBrain     │
                                                  │              │
                                                  │  ┌────────┐  │
                                                  │  │subjects│  │
                                                  │  └────────┘  │
                                                  │  ┌────────┐  │
                                                  │  │ oauth_ │  │
                                                  │  │tokens  │  │
                                                  │  │+sub_id │  │
                                                  │  └────────┘  │
                                                  └──────────────┘

   3. Gateway uses the per-turn token for MCP calls.
   4. GBrain's verifyAccessToken resolves Saad's source_id +
      allowed_sources from the subjects row. RLS applies at every
      SQL read.
```

## Setup

```bash
# 1. Register the gateway as a delegator client.
gbrain auth register-client "whatsapp-gateway" \
  --scopes "read write" \
  --grant-types "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange"
#   → Note the client_id + client_secret.

# 2. Register each verified WhatsApp user as a subject.
#    The WhatsApp lid is the natural subject_id — already unique,
#    already verified by your gateway's number-onboarding flow.
gbrain auth subjects add "923354811400@lid" \
  --name "Saad" --role super_admin \
  --source general \
  --allowed-sources "general,leadership,finance,ceos,super_admin"

gbrain auth subjects add "923001234567@lid" \
  --name "Staff Member" --role staff \
  --source general \
  --allowed-sources "general"

# 3. Authorize the gateway to act on behalf of every subject.
gbrain auth allow-exchange <gateway-client-id> --subjects "*"
```

## Gateway side (pseudo-code)

```python
import httpx
import time

# Cache exchanged tokens for ~5 min. Hot path: one exchange per
# subject per cache window, NOT per MCP call.
class TokenCache:
    def __init__(self, gbrain_url, client_id, client_secret):
        self.url = gbrain_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache = {}                           # subject_id → (token, expires_at)

    def for_subject(self, subject_id: str) -> str:
        now = time.time()
        cached = self.cache.get(subject_id)
        if cached and cached[1] > now + 30:       # 30s safety margin
            return cached[0]

        resp = httpx.post(
            f"{self.url}/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "subject_token": subject_id,
                "subject_token_type": "urn:gbrain:params:oauth:token-type:subject-id",
                "scope": "read write",
            },
        )
        resp.raise_for_status()
        body = resp.json()
        self.cache[subject_id] = (body["access_token"], now + body["expires_in"])
        return body["access_token"]


# Per-turn usage:
def handle_whatsapp_turn(sender_lid: str, message: str):
    token = token_cache.for_subject(sender_lid)
    # Use `token` as the Bearer for any /mcp call this turn.
    # GBrain resolves the subject's source + allowed_sources and
    # enforces RLS automatically.
```

## What the RLS isolation actually looks like

Suppose the brain has documents in 4 sources: `general`, `leadership`,
`finance`, `super_admin`. Two subjects:

| Subject | `source_id` | `allowed_sources` |
|---|---|---|
| `staff@lid` | general | `[general]` |
| `saad@lid` (super_admin) | general | `[general, leadership, finance, super_admin]` |

The same MCP call, exchanged for each subject:

| Call | `staff@lid` token | `saad@lid` token |
|---|---|---|
| `query "Q3 strategy"` | hits in `general` only | hits across all 4 sources |
| `get_page leadership/strategy-q3` | `page_not_found` (RLS-rejected at SQL) | success |
| `search "salary review"` | hits in `general` only | hits in `general` + `finance` |
| `list_pages source=super_admin` | RLS-rejected | success |

Database-enforced. No persona-prompt heuristics, no application-layer
filtering. If the model hallucinates a query for a forbidden source,
Postgres returns zero rows — full stop.

## Audit trail

Every MCP request gets logged with:

- `client_id` → the gateway (`gbrain_cl_xxx`, "whatsapp-gateway")
- `subject_id` → the end-user (`923354811400@lid`, "Saad")

So `gbrain doctor`, your admin dashboard, and SOC2-style audit reports
all show *which human* every operation acted on behalf of. The shared
service account is gone.

## Onboarding new users

When a brand-new WhatsApp number messages the gateway:

1. The gateway runs its existing pending-user flow (whatever your
   approval gate looks like).
2. On approval, call `gbrain auth subjects add <lid>` with the
   appropriate role + source mappings.
3. Next message from that user works immediately. No restart, no
   client re-registration.

## Offboarding

```bash
gbrain auth subjects remove "923354811400@lid"
```

Soft-deletes the subject row. All tokens previously minted for that
subject — including ones still cached in the gateway — fail at the
next `verifyAccessToken` call. There's no "stale token can keep
reading" window.

## See also

- [docs/integrations/on-behalf-of.md](../docs/integrations/on-behalf-of.md)
  for the spec-level reference.
- [docs/integrations/credential-gateway.md](../docs/integrations/credential-gateway.md)
  for the related (but different) pattern of injecting downstream
  service credentials.
