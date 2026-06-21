/**
 * GBrain OAuth 2.1 Provider — implements MCP SDK's OAuthServerProvider.
 *
 * Backed by raw SQL (PGLite or Postgres), not the BrainEngine interface.
 * OAuth is infrastructure, not brain operations.
 *
 * Supports:
 * - Client registration (manual via CLI or Dynamic Client Registration)
 * - Authorization code flow with PKCE (for ChatGPT, browser-based clients)
 * - Client credentials flow (for machine-to-machine: Perplexity, Claude)
 * - Token refresh with rotation
 * - Token revocation
 * - Legacy access_tokens fallback for backward compat
 */

import type { Response } from 'express';
import type {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { hashToken, generateToken, isUndefinedColumnError } from './utils.ts';
import { hasScope, assertAllowedScopes, parseScopeString, InvalidScopeError } from './scope.ts';
import { safeHexEqual } from './timing-safe.ts';
import type { SqlQuery, SqlValue } from './sql-query.ts';
export type { SqlQuery, SqlValue };

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Convert a JS array to a PostgreSQL array literal for PGLite compat.
 *
 * PGLite's `db.query(sql, params)` rejects JS arrays bound directly to TEXT[]
 * columns ("insufficient data left in message"), so we hand-build the array
 * literal `{...}` and let Postgres parse it on insert.
 *
 * SECURITY: every element is wrapped in double quotes with `"` and `\`
 * escaped. Without this, an element containing a comma (e.g., a malicious
 * `redirect_uri` containing `,`) would be parsed by Postgres as MULTIPLE
 * array elements, smuggling values past validation. See CSO finding #5.
 */
function pgArray(arr: string[]): string {
  if (!arr || arr.length === 0) return '{}';
  const escaped = arr.map(s => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
  return `{${escaped.join(',')}}`;
}

/**
 * Allow-list of RFC 7591 §2 `token_endpoint_auth_method` values gbrain
 * accepts at registration. Three values, chosen because the SDK's
 * `mcpAuthRouter` advertises exactly these three in
 * `token_endpoint_auth_methods_supported`:
 *
 * - `client_secret_post` — confidential client; secret in body (default)
 * - `client_secret_basic` — confidential client; secret in Authorization header
 * - `none` — public PKCE-only client (Claude Code, Cursor, ChatGPT custom connector)
 *
 * Three call sites enforce this set:
 *   1. CLI `gbrain auth register-client` (src/commands/auth.ts)
 *   2. Admin `POST /admin/api/register-client` (src/commands/serve-http.ts)
 *   3. DCR `POST /register` (this file, GBrainClientsStore.registerClient)
 *
 * **Read-tolerant by design.** `getClient` returns whatever is stored
 * verbatim — legacy rows with non-allowlist values (e.g. pre-v0.41.3
 * direct UPDATEs) continue to function. The validator gates new writes
 * ONLY; we don't break operators with hand-edited rows on upgrade.
 */
/**
 * RFC 8693 §3 — `subject_token_type` URI values gbrain understands at the
 * token-exchange grant. A delegator client identifies the subject it is
 * acting on behalf of by sending one of these in `subject_token_type`.
 *
 * - `urn:gbrain:params:oauth:token-type:subject-id` — the `subject_token`
 *   parameter is the literal opaque subject identifier (e.g., a WhatsApp
 *   lid, Slack user id, email). Only honored when the calling client is
 *   registered with `token_exchange_allowed = true` AND the requested
 *   subject is in its `allowed_subjects` list (or the client is a
 *   wildcard delegator). This is the "trusted upstream" delegation
 *   pattern from the MCP literature: the delegator vouches for the
 *   subject identity it carries, and the brain trusts that assertion
 *   only because the client is explicitly allow-listed for it.
 *
 * Future: a signed-assertion variant (e.g., `urn:ietf:params:oauth:
 * token-type:jwt`) is a clean extension — same handler, additional
 * verification on the subject_token before resolving the subject row.
 */
export const SUBJECT_TOKEN_TYPE_SUBJECT_ID = 'urn:gbrain:params:oauth:token-type:subject-id';

/**
 * RFC 8693 §2.1 / §2.2 — `requested_token_type` value gbrain returns.
 * Always an access token; refresh tokens are intentionally NOT issued
 * for subject-scoped grants so a compromised delegator can't rotate
 * indefinitely against a single subject (short-lived only, defense in
 * depth alongside the calling client's secret).
 */
export const ISSUED_TOKEN_TYPE_ACCESS = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * Typed OAuth error envelope (RFC 6749 §5.2 / RFC 8693 §2.4 vocabulary).
 *
 * The `code` is the spec-defined identifier returned on the wire as
 * `error`. The constructor's `message` is the SAFE-FOR-WIRE description
 * (no caller input echoed) — surfaced as `error_description`. Callers
 * that want richer detail for logs should pass `logDetail` separately;
 * the wire boundary discards it.
 *
 * Why this exists: pre-typed-error, throw sites returned bare `Error`
 * with messages like `Subject not in client's allowed_subjects: ${id}`,
 * which the serve-http layer string-matched onto status codes. That
 * leaked caller input into the response body AND was brittle. With
 * typed errors the dispatch is exhaustive at the type level and the
 * description is always a fixed safe string.
 */
export class OAuthGrantError extends Error {
  constructor(
    public readonly code:
      | 'invalid_request'
      | 'invalid_client'
      | 'invalid_grant'
      | 'invalid_scope'
      | 'unauthorized_client'
      | 'unsupported_grant_type'
      | 'invalid_target',
    /** Safe-for-wire description. NEVER includes caller-supplied input. */
    description: string,
    /** Detailed message for server-side logs ONLY. May include input. */
    public readonly logDetail?: string,
  ) {
    super(description);
    this.name = 'OAuthGrantError';
  }
}

export type TokenEndpointAuthMethod = 'client_secret_post' | 'client_secret_basic' | 'none';

export const ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS = new Set<TokenEndpointAuthMethod>([
  'client_secret_post',
  'client_secret_basic',
  'none',
]);

export class InvalidTokenEndpointAuthMethodError extends Error {
  readonly code = 'invalid_token_endpoint_auth_method';
  constructor(value: unknown) {
    super(
      `Invalid token_endpoint_auth_method: ${JSON.stringify(value)}. ` +
      `Expected one of: ${Array.from(ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS).join(', ')}. ` +
      `RFC 7591 §2 — see https://datatracker.ietf.org/doc/html/rfc7591#section-2.`,
    );
    this.name = 'InvalidTokenEndpointAuthMethodError';
  }
}

/**
 * Validate a token_endpoint_auth_method value at the registration boundary.
 * Throws `InvalidTokenEndpointAuthMethodError` on rejection; returns the
 * typed value on success. Returns `'client_secret_post'` for undefined input
 * (RFC 7591 default).
 *
 * Apply at every registration entry point (CLI, admin endpoint, DCR). Do
 * NOT apply on read — legacy oauth_clients rows with non-allowlist values
 * must continue to function unchanged.
 */
export function validateTokenEndpointAuthMethod(value: unknown): TokenEndpointAuthMethod {
  if (value === undefined || value === null || value === '') return 'client_secret_post';
  if (typeof value !== 'string') throw new InvalidTokenEndpointAuthMethodError(value);
  if (!ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS.has(value as TokenEndpointAuthMethod)) {
    throw new InvalidTokenEndpointAuthMethodError(value);
  }
  return value as TokenEndpointAuthMethod;
}

/**
 * Validate a redirect_uri per RFC 6749 §3.1.2.1.
 *
 * Production redirect_uris MUST be HTTPS. The only allowed plaintext
 * exceptions are loopback (127.0.0.1, ::1, localhost) which are unreachable
 * from the network. Throws a descriptive error on rejection.
 *
 * Used by the DCR (Dynamic Client Registration) path; the CLI registration
 * path trusts the operator and bypasses this gate.
 */
function validateRedirectUri(uri: string): void {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error(`Invalid redirect_uri: not a parseable URL: ${uri}`);
  }
  const isLoopback = parsed.hostname === 'localhost'
    || parsed.hostname === '127.0.0.1'
    || parsed.hostname === '[::1]'
    || parsed.hostname === '::1';
  if (parsed.protocol === 'https:') return;
  if (parsed.protocol === 'http:' && isLoopback) return;
  throw new Error(
    `redirect_uri must use https:// (or http://localhost for loopback): ${uri}`,
  );
}

/**
 * Coerce an OAuth timestamp column (Unix epoch seconds, BIGINT) into a JS
 * number, or undefined for SQL NULL.
 *
 * Why this exists: postgres.js with `prepare: false` (the auto-detected setting
 * on Supabase PgBouncer / port 6543; see src/core/db.ts:resolvePrepare) returns
 * BIGINT columns as strings. Two surfaces break on that: (1) the MCP SDK's
 * bearerAuth middleware checks `typeof authInfo.expiresAt === 'number'` and
 * rejects strings; (2) RFC 7591 §3.2.1 requires `client_id_issued_at` and
 * `client_secret_expires_at` to be JSON numbers in DCR responses, not strings.
 *
 * Throws on non-finite (NaN/Infinity) so corrupt rows fail loud at the boundary
 * instead of letting `expiresAt: NaN` flow through to the SDK as a fake-valid
 * token. Returns undefined for SQL NULL so callers decide NULL semantics
 * explicitly. For OAuth, the comparison sites treat NULL as "expired"
 * (fail-closed); the DCR response sites preserve undefined per RFC 7591
 * (the `client_secret_expires_at` field is optional, undefined means
 * "did not expire").
 */
export function coerceTimestamp(value: unknown): number | undefined {
  if (value === null || value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n)) {
    throw new Error(`coerceTimestamp: non-finite timestamp value ${JSON.stringify(value)}`);
  }
  return n;
}

interface GBrainOAuthProviderOptions {
  sql: SqlQuery;
  /** Default token TTL in seconds (default: 3600 = 1 hour) */
  tokenTtl?: number;
  /** Default refresh token TTL in seconds (default: 30 days) */
  refreshTtl?: number;
  /**
   * Disable Dynamic Client Registration (RFC 7591) while keeping the rest of
   * the OAuth surface intact. When true, `clientsStore.registerClient` is not
   * surfaced to the SDK router, so POST `/register` returns 404 even though
   * the underlying provider can still register clients programmatically via
   * `registerClientManual`. Replaces the previous monkey-patching pattern in
   * serve-http.ts (cleanup, not a security fix — DCR was never reachable
   * before mcpAuthRouter ran).
   */
  dcrDisabled?: boolean;
}

// ---------------------------------------------------------------------------
// Clients Store
// ---------------------------------------------------------------------------

class GBrainClientsStore implements OAuthRegisteredClientsStore {
  constructor(private sql: SqlQuery) {}

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    const rows = await this.sql`
      SELECT client_id, client_secret_hash, client_name, redirect_uris,
             grant_types, scope, token_endpoint_auth_method,
             client_id_issued_at, client_secret_expires_at
      FROM oauth_clients WHERE client_id = ${clientId}
    `;
    if (rows.length === 0) return undefined;
    const r = rows[0];
    // v0.34.1 (#909): public clients (token_endpoint_auth_method='none')
    // have client_secret_hash = NULL. Normalize SQL NULL to JS undefined
    // so SDK middleware that checks `client.client_secret === undefined`
    // (not `=== null`) correctly identifies the client as public and
    // skips the secret-comparison branch on /token.
    const rawSecret = r.client_secret_hash;
    return {
      client_id: r.client_id as string,
      client_secret: rawSecret == null ? undefined : (rawSecret as string),
      client_name: r.client_name as string,
      redirect_uris: (r.redirect_uris as string[]) || [],
      grant_types: (r.grant_types as string[]) || ['client_credentials'],
      scope: r.scope as string | undefined,
      token_endpoint_auth_method: r.token_endpoint_auth_method as string | undefined,
      client_id_issued_at: coerceTimestamp(r.client_id_issued_at),
      client_secret_expires_at: coerceTimestamp(r.client_secret_expires_at),
    };
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>,
  ): Promise<OAuthClientInformationFull> {
    // Enforce HTTPS for all redirect_uris on the DCR path (RFC 6749 §3.1.2.1).
    // Without this, an attacker could register a non-loopback http:// URI and
    // exfiltrate auth codes over plaintext. CLI registrations bypass this gate
    // (operators are trusted; they can register http:// for testing).
    for (const uri of client.redirect_uris || []) {
      validateRedirectUri(String(uri));
    }

    // v0.28: ALLOWED_SCOPES allowlist. RFC 6749 §5.2 invalid_scope. The DCR
    // path is reachable by any unauthenticated network caller when --enable-dcr
    // is on, so this is the security-relevant gate (manual CLI registration
    // is operator-trusted).
    assertAllowedScopes(parseScopeString(client.scope));

    // v0.41.3 (T5): validate token_endpoint_auth_method on the DCR path so
    // `--enable-dcr` is not the looser entry point. CLI and admin paths gate
    // through the same `validateTokenEndpointAuthMethod` helper — all three
    // registration entry points share one allow-list.
    const authMethod = validateTokenEndpointAuthMethod(client.token_endpoint_auth_method);

    const clientId = generateToken('gbrain_cl_');
    // v0.34.1 (#909): RFC 7591 §2 — clients that authenticate at the token
    // endpoint via PKCE alone declare `token_endpoint_auth_method: "none"`.
    // For those clients the authorization server MUST NOT issue a client
    // secret. Pre-fix, unconditional secret generation made the MCP SDK's
    // clientAuth middleware check `client.client_secret` on every request,
    // rejecting valid public-client (Claude Code, Cursor) flows.
    //
    // We persist secret_hash = NULL for public clients so `getClient` and
    // the SDK's clientAuth path can detect them via `client_secret_hash IS
    // NULL` and skip the secret comparison. Confidential clients (default
    // `client_secret_post` and explicit `client_secret_basic`) still mint
    // a secret as before.
    const isPublicClient = authMethod === 'none';
    const clientSecret = isPublicClient ? undefined : generateToken('gbrain_cs_');
    const secretHash = clientSecret ? hashToken(clientSecret) : null;
    const now = Math.floor(Date.now() / 1000);

    // v0.34.1 (#861, D2 + D13 + #876): DCR clients get source_id='default'
    // (matches legacy fallback) and federated_read=['default'] (read scope
    // == write scope). Operators who need narrower / wider scope rescope
    // via the CLI later. Pre-v60/v61 brain falls through to the legacy
    // projection (no source_id / federated_read column yet).
    try {
      await this.sql`
        INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                    grant_types, scope, token_endpoint_auth_method,
                                    client_id_issued_at, source_id, federated_read)
        VALUES (${clientId}, ${secretHash}, ${client.client_name || 'unnamed'},
                ${pgArray((client.redirect_uris || []).map(String))},
                ${pgArray(client.grant_types || ['client_credentials'])},
                ${client.scope || ''}, ${authMethod},
                ${now}, ${'default'}, ${pgArray(['default'])})
      `;
    } catch (err) {
      if (isUndefinedColumnError(err, 'federated_read')) {
        try {
          await this.sql`
            INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                        grant_types, scope, token_endpoint_auth_method,
                                        client_id_issued_at, source_id)
            VALUES (${clientId}, ${secretHash}, ${client.client_name || 'unnamed'},
                    ${pgArray((client.redirect_uris || []).map(String))},
                    ${pgArray(client.grant_types || ['client_credentials'])},
                    ${client.scope || ''}, ${authMethod},
                    ${now}, ${'default'})
          `;
        } catch (err2) {
          if (isUndefinedColumnError(err2, 'source_id')) {
            await this.sql`
              INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                          grant_types, scope, token_endpoint_auth_method,
                                          client_id_issued_at)
              VALUES (${clientId}, ${secretHash}, ${client.client_name || 'unnamed'},
                      ${pgArray((client.redirect_uris || []).map(String))},
                      ${pgArray(client.grant_types || ['client_credentials'])},
                      ${client.scope || ''}, ${authMethod},
                      ${now})
            `;
          } else {
            throw err2;
          }
        }
      } else if (isUndefinedColumnError(err, 'source_id')) {
        await this.sql`
          INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                      grant_types, scope, token_endpoint_auth_method,
                                      client_id_issued_at)
          VALUES (${clientId}, ${secretHash}, ${client.client_name || 'unnamed'},
                  ${pgArray((client.redirect_uris || []).map(String))},
                  ${pgArray(client.grant_types || ['client_credentials'])},
                  ${client.scope || ''}, ${authMethod},
                  ${now})
        `;
      } else {
        throw err;
      }
    }

    // Public clients: omit `client_secret` entirely from the response so
    // the wire payload matches RFC 7591 §3.2.1 ("if the client is a
    // public client, the authorization server MUST NOT issue a client
    // secret"). Confidential clients return the freshly-generated secret
    // exactly once — same shape as before.
    const response: OAuthClientInformationFull = {
      ...client,
      client_id: clientId,
      client_id_issued_at: now,
    };
    if (clientSecret) response.client_secret = clientSecret;
    return response;
  }
}

// ---------------------------------------------------------------------------
// OAuth Provider
// ---------------------------------------------------------------------------

export class GBrainOAuthProvider implements OAuthServerProvider {
  private sql: SqlQuery;
  private _clientsStore: GBrainClientsStore;
  private readonly dcrDisabled: boolean;
  private tokenTtl: number;
  private refreshTtl: number;

  constructor(options: GBrainOAuthProviderOptions) {
    this.sql = options.sql;
    this._clientsStore = new GBrainClientsStore(this.sql);
    this.dcrDisabled = options.dcrDisabled === true;
    this.tokenTtl = options.tokenTtl || 3600;
    this.refreshTtl = options.refreshTtl || 30 * 24 * 3600;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    if (this.dcrDisabled) {
      // Surface getClient only — without registerClient the SDK's mcpAuthRouter
      // does not wire up the /register DCR endpoint. Replaces the prior
      // monkey-patch in serve-http.ts; the outcome is identical (DCR off-by-
      // default), but the API expresses intent on the constructor instead of
      // requiring callers to mutate `_clientsStore` after construction.
      return {
        getClient: this._clientsStore.getClient.bind(this._clientsStore),
      } as OAuthRegisteredClientsStore;
    }
    return this._clientsStore;
  }

  // -------------------------------------------------------------------------
  // Authorization Code Flow
  // -------------------------------------------------------------------------

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    const code = generateToken('gbrain_code_');
    const codeHash = hashToken(code);
    const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minute TTL

    // Scope clamp (RFC 6749 §3.3): the SDK's authorize handler splits
    // `?scope=...` verbatim and forwards the raw list to the provider, so
    // the provider MUST clamp against the client's registered grant. Without
    // this, a `read`-registered client requesting `?scope=admin` would have
    // `['admin']` stored in oauth_codes and returned by exchangeAuthorizationCode
    // as a fully-admin access token. Mirrors the filter pattern already used
    // by exchangeClientCredentials (this file) and exchangeRefreshToken's F3
    // subset enforcement (RFC 6749 §6) so all three grant entry points clamp
    // consistently. Empty/omitted requested scope inherits the empty-stored
    // shape (existing behavior; not a security boundary).
    const allowedScopes = parseScopeString(client.scope);
    const grantedScopes = (params.scopes || []).filter(s => hasScope(allowedScopes, s));

    await this.sql`
      INSERT INTO oauth_codes (code_hash, client_id, scopes, code_challenge,
                                code_challenge_method, redirect_uri, state, resource, expires_at)
      VALUES (${codeHash}, ${client.client_id},
              ${pgArray(grantedScopes)},
              ${params.codeChallenge}, ${'S256'},
              ${params.redirectUri}, ${params.state || null},
              ${params.resource?.toString() || null}, ${expiresAt})
    `;

    // Redirect back with the code
    const redirectUrl = new URL(params.redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (params.state) redirectUrl.searchParams.set('state', params.state);
    res.redirect(redirectUrl.toString());
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const codeHash = hashToken(authorizationCode);
    // F1 hardening: bind client_id atomically so a wrong client cannot read
    // another client's PKCE challenge. Pre-fix the SELECT didn't filter on
    // client_id at all.
    const rows = await this.sql`
      SELECT code_challenge FROM oauth_codes
      WHERE code_hash = ${codeHash}
        AND client_id = ${client.client_id}
        AND expires_at > ${Math.floor(Date.now() / 1000)}
    `;
    if (rows.length === 0) throw new Error('Authorization code not found or expired');
    return rows[0].code_challenge as string;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const codeHash = hashToken(authorizationCode);
    const now = Math.floor(Date.now() / 1000);

    // F1 + F7c hardening: bind client_id AND redirect_uri atomically into the
    // DELETE WHERE clause. RFC 6749 §10.5 requires auth codes be single-use;
    // RFC 6749 §4.1.3 requires the token endpoint validate redirect_uri
    // matches the value sent at /authorize. The previous SELECT-then-compare
    // pattern (a) burned the code on the wrong-client path so the legitimate
    // client could not retry, and (b) ignored redirect_uri on exchange
    // entirely. With RETURNING, the second request — or any wrong-client /
    // wrong-redirect-uri attempt — gets zero rows back and fails cleanly.
    // The legitimate client's code stays available for one valid redemption.
    //
    // Use `redirectUri !== undefined` rather than truthy — an attacker
    // submitting `redirect_uri=""` (empty string) at /token would otherwise
    // hit the falsy branch and bypass the binding entirely.
    const rows = redirectUri !== undefined
      ? await this.sql`
          DELETE FROM oauth_codes
          WHERE code_hash = ${codeHash}
            AND client_id = ${client.client_id}
            AND redirect_uri = ${redirectUri}
            AND expires_at > ${now}
          RETURNING client_id, scopes, resource
        `
      : await this.sql`
          DELETE FROM oauth_codes
          WHERE code_hash = ${codeHash}
            AND client_id = ${client.client_id}
            AND expires_at > ${now}
          RETURNING client_id, scopes, resource
        `;
    if (rows.length === 0) throw new Error('Authorization code not found or expired');

    const codeRow = rows[0];

    // Issue tokens
    const scopes = (codeRow.scopes as string[]) || [];
    return this.issueTokens(client.client_id, scopes, resource, true);
  }

  // -------------------------------------------------------------------------
  // Refresh Token
  // -------------------------------------------------------------------------

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const tokenHash = hashToken(refreshToken);
    const now = Math.floor(Date.now() / 1000);

    // F2 hardening: bind client_id atomically into the DELETE WHERE clause.
    // RFC 6749 §10.4 detection of stolen refresh tokens depends on second-use
    // failure. The previous SELECT-then-DELETE pattern + post-hoc client
    // compare let an attacker who guessed/stole a refresh token burn it on
    // the wrong-client path, defeating the stolen-token signal for the
    // legitimate client. With the predicate in the DELETE, wrong-client
    // attempts get zero rows back; the legitimate client retains the row
    // for one valid rotation.
    const rows = await this.sql`
      DELETE FROM oauth_tokens
      WHERE token_hash = ${tokenHash}
        AND token_type = 'refresh'
        AND client_id = ${client.client_id}
      RETURNING client_id, scopes, expires_at
    `;
    if (rows.length === 0) throw new Error('Refresh token not found');

    const row = rows[0];
    // NULL expires_at is treated as expired (fail-closed). Schema permits NULL
    // even though issueTokens always sets it, so a corrupt or hand-modified row
    // can't ride past validation.
    const expiresAt = coerceTimestamp(row.expires_at);
    if (expiresAt === undefined || expiresAt < now) throw new Error('Refresh token expired');

    // F3 hardening: requested scopes on refresh MUST be a subset of the
    // original grant on this refresh token's row. RFC 6749 §6: "the scope of
    // the access token … MUST NOT include any scope not originally granted by
    // the resource owner." Scope is checked against the row's scopes (the
    // grant), NOT against the client's currently-allowed scopes (which can
    // expand later). Omitted scope (`undefined`) inherits the original grant
    // verbatim and stays distinct from an explicit empty array.
    //
    // v0.28: hasScope replaces exact-string-match so an `admin` grant CAN
    // refresh down to `sources_admin` (admin implies all). Without this,
    // gstack /setup-gbrain Path 4 — which mints a sources_admin-scoped
    // refresh — would fail when the brain admin's bootstrap token was
    // issued at the `admin` tier.
    const grantedScopes = (row.scopes as string[]) || [];
    if (scopes && scopes.some(s => !hasScope(grantedScopes, s))) {
      throw new Error('Requested scope exceeds refresh token grant');
    }
    const tokenScopes = scopes ?? grantedScopes;
    return this.issueTokens(client.client_id, tokenScopes, resource, true);
  }

  // -------------------------------------------------------------------------
  // Token Verification
  // -------------------------------------------------------------------------

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const tokenHash = hashToken(token);
    const now = Math.floor(Date.now() / 1000);

    // Try OAuth tokens first. JOIN oauth_clients in the same query so
    // verifyAccessToken returns client_name AND source_id in AuthInfo —
    // eliminates the separate per-request lookup at serve-http.ts that
    // was the N+1 hot path (see PR #586 review D14=B; v0.34.1 #861 D2
    // adds the source_id thread on the same JOIN).
    //
    // v0.34.1 (#861): the JOIN guards on a c.source_id column that
    // migration v60 adds. Pre-v60 brains throw a "column does not exist"
    // error here — caught at the boundary via isUndefinedColumnError so
    // unmigrated brains degrade to "no source scope" rather than refusing
    // every token verification.
    let oauthRows: Record<string, unknown>[];
    try {
      // Primary projection (post-v117): includes oauth_tokens.subject_id so
      // verifyAccessToken can detect token-exchange-minted tokens and
      // resolve the subject's effective RLS scope below. Pre-v117 brain →
      // subject_id column missing → falls through to the v61+ projection
      // (no subject column), which is identical to the previous primary.
      oauthRows = await this.sql`
        SELECT t.client_id, t.scopes, t.expires_at, t.resource, t.subject_id,
               c.client_name, c.source_id, c.federated_read
        FROM oauth_tokens t
        LEFT JOIN oauth_clients c ON c.client_id = t.client_id
        WHERE t.token_hash = ${tokenHash} AND t.token_type = 'access'
      `;
    } catch (errSubject) {
      if (!isUndefinedColumnError(errSubject, 'subject_id')) throw errSubject;
      try {
        // v61+ projection (pre-v117, has federated_read but no subject_id).
        oauthRows = await this.sql`
          SELECT t.client_id, t.scopes, t.expires_at, t.resource, c.client_name,
                 c.source_id, c.federated_read
          FROM oauth_tokens t
          LEFT JOIN oauth_clients c ON c.client_id = t.client_id
          WHERE t.token_hash = ${tokenHash} AND t.token_type = 'access'
        `;
      } catch (err) {
      // v0.34.1: pre-v60 brain → source_id column missing. Pre-v61 brain →
      // federated_read column missing. Both classes degrade to legacy
      // projection so auth keeps working until the operator runs
      // apply-migrations. Probe both column names so partial-upgrade brains
      // (v60 applied but v61 didn't yet) also fall through cleanly.
      if (isUndefinedColumnError(err, 'source_id') || isUndefinedColumnError(err, 'federated_read')) {
        // Try the v60-only projection first (source_id but no federated_read).
        try {
          oauthRows = await this.sql`
            SELECT t.client_id, t.scopes, t.expires_at, t.resource, c.client_name, c.source_id
            FROM oauth_tokens t
            LEFT JOIN oauth_clients c ON c.client_id = t.client_id
            WHERE t.token_hash = ${tokenHash} AND t.token_type = 'access'
          `;
        } catch (err2) {
          if (isUndefinedColumnError(err2, 'source_id')) {
            // Truly pre-v60: no source_id either. Pre-v0.34 projection.
            oauthRows = await this.sql`
              SELECT t.client_id, t.scopes, t.expires_at, t.resource, c.client_name
              FROM oauth_tokens t
              LEFT JOIN oauth_clients c ON c.client_id = t.client_id
              WHERE t.token_hash = ${tokenHash} AND t.token_type = 'access'
            `;
          } else {
            throw err2;
          }
        }
      } else {
        throw err;
      }
    }
    }

    if (oauthRows.length > 0) {
      const row = oauthRows[0];
      // NULL expires_at is treated as expired (fail-closed). Schema permits NULL,
      // and the SDK's bearerAuth requires `typeof expiresAt === 'number'` — we
      // throw here rather than return an undefined-bearing AuthInfo.
      const expiresAt = coerceTimestamp(row.expires_at);
      if (expiresAt === undefined || expiresAt < now) {
        throw new InvalidTokenError('Token expired');
      }

      // RFC 8693 (v117): token-exchange tokens carry a subject_id. When
      // set, the effective RLS scope (source_id + allowedSources) comes
      // from the `subjects` row, NOT the calling client's row. Downstream
      // consumers (HTTP transport → sourceScopeOpts) read these fields
      // verbatim — the substitution is invisible to them by design. The
      // `clientId` in AuthInfo still reflects the calling delegator so
      // audit logs read "Hermes acting for subject Saad". Soft-deleted
      // subjects fail closed (treated as unknown).
      //
      // Pre-v117 brain: the subject_id column is missing — caught at the
      // top-level catch in the SELECT above and falls through to the
      // legacy projection. So we don't need to probe here.
      const subjectIdRaw = (row as Record<string, unknown>).subject_id;
      if (typeof subjectIdRaw === 'string' && subjectIdRaw.length > 0) {
        const subjectRows = await this.sql`
          SELECT subject_id, display_name, role, source_id, allowed_sources
          FROM subjects
          WHERE subject_id = ${subjectIdRaw} AND deleted_at IS NULL
        `;
        if (subjectRows.length === 0) {
          // Subject was deleted after this token was minted. Fail closed —
          // a compromised delegator should not be able to keep using
          // tokens it minted for users that have been revoked.
          throw new InvalidTokenError('Subject revoked');
        }
        const sRow = subjectRows[0];
        const sFederated = sRow.allowed_sources;
        const sAllowed = Array.isArray(sFederated)
          ? (sFederated as string[])
          : undefined;
        return {
          token,
          clientId: row.client_id as string,
          clientName: (row.client_name as string | null) ?? undefined,
          scopes: (row.scopes as string[]) || [],
          expiresAt,
          resource: row.resource ? new URL(row.resource as string) : undefined,
          sourceId: (sRow.source_id as string | null) ?? undefined,
          allowedSources: sAllowed,
          subjectId: sRow.subject_id as string,
        } as AuthInfo;
      }

      // v0.34.1 (#876): federated_read normalization. SELECT returns
      // either a JS array (Postgres / PGLite text[] driver mapping) or
      // undefined when the legacy projection ran (pre-v61 brain). Empty
      // array vs undefined matters: empty array = explicit no-federated-
      // read; undefined = column missing on this brain.
      const federatedRaw = row.federated_read;
      const allowedSources = Array.isArray(federatedRaw)
        ? (federatedRaw as string[])
        : undefined;
      return {
        token,
        clientId: row.client_id as string,
        clientName: (row.client_name as string | null) ?? undefined,
        scopes: (row.scopes as string[]) || [],
        expiresAt,
        resource: row.resource ? new URL(row.resource as string) : undefined,
        // v0.34.1 (#861, D2): source-isolation scope from oauth_clients.
        // Undefined when the row predates v60 or when the brain itself
        // predates v60 (fell through to the legacy projection above).
        sourceId: (row.source_id as string | null) ?? undefined,
        // v0.34.1 (#876): federated read scope. sourceScopeOpts in
        // operations.ts prefers this array over scalar sourceId when set
        // and non-empty.
        allowedSources,
      } as AuthInfo;
    }

    // Fallback: legacy access_tokens table (backward compat)
    const legacyRows = await this.sql`
      SELECT name FROM access_tokens
      WHERE token_hash = ${tokenHash} AND revoked_at IS NULL
    `;

    if (legacyRows.length > 0) {
      // Legacy tokens get full admin access (grandfather in).
      // For legacy tokens, name = clientId = clientName (single identifier).
      // Update last_used_at
      await this.sql`
        UPDATE access_tokens SET last_used_at = now() WHERE token_hash = ${tokenHash}
      `;
      const name = legacyRows[0].name as string;
      return {
        token,
        clientId: name,
        clientName: name,
        scopes: ['read', 'write', 'admin'],
        expiresAt: Math.floor(Date.now() / 1000) + 365 * 24 * 3600, // Legacy tokens never expire — set 1yr future
        // v0.34.1 (#861, D13): legacy bearer tokens default to 'default'
        // source — matches the pre-v0.34 effective behavior where the
        // serve-http transport fell back to GBRAIN_SOURCE/'default' for
        // any caller without explicit scope. Operators who want a
        // narrower scope for legacy tokens migrate to OAuth.
        sourceId: 'default',
      } as AuthInfo;
    }

    throw new InvalidTokenError('Invalid token');
  }

  // -------------------------------------------------------------------------
  // Token Revocation
  // -------------------------------------------------------------------------

  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    const tokenHash = hashToken(request.token);
    // F4 hardening: bind client_id so a client can only revoke its own
    // tokens. RFC 7009 §2.1: "The authorization server first validates the
    // client credentials … and then verifies whether the token was issued
    // to the client making the revocation request." Pre-fix, any
    // authenticated client that knew (or guessed) another client's token
    // hash could revoke it.
    await this.sql`
      DELETE FROM oauth_tokens
      WHERE token_hash = ${tokenHash}
        AND client_id = ${client.client_id}
    `;
  }

  // -------------------------------------------------------------------------
  // Confidential-client authentication (shared by /token grant handlers)
  // -------------------------------------------------------------------------

  /**
   * Resolve + authenticate a confidential OAuth client via its
   * client_id + client_secret, including the soft-delete probe. Returns
   * the validated client on success; throws `OAuthGrantError` with
   * code `'invalid_client'` on every failure mode (unknown client,
   * public client, wrong secret, revoked client).
   *
   * This is the shared building block behind:
   *   - `verifyConfidentialClientSecret` (legacy public surface; wraps
   *     to translate OAuthGrantError → plain Error so the auth_code +
   *     refresh_token handlers' existing string-match dispatch in
   *     serve-http.ts keeps working)
   *   - `exchangeSubjectToken` (RFC 8693; uses the typed error directly
   *     so the wire-boundary dispatch is exhaustive at the type level)
   *
   * Constant-time hex compare via safeHexEqual; CWE-208 hardened.
   */
  private async _authenticateConfidentialClient(
    clientId: string,
    presentedSecret: string,
  ): Promise<OAuthClientInformationFull> {
    const client = await this._clientsStore.getClient(clientId);
    if (!client) throw new OAuthGrantError('invalid_client', 'Invalid client');
    // Public client (token_endpoint_auth_method='none') — refuses to
    // use this hash-compare path. PKCE is the canonical surface for
    // public clients via the SDK.
    if (client.client_secret === undefined) {
      throw new OAuthGrantError('invalid_client', 'Invalid client');
    }
    const presentedHash = hashToken(presentedSecret);
    if (!safeHexEqual(client.client_secret, presentedHash)) {
      throw new OAuthGrantError('invalid_client', 'Invalid client');
    }
    // Soft-delete probe. The deleted_at column is recent; pre-migration
    // brains lack it — tolerate that one specific column-missing error
    // without swallowing real failures (lock timeouts, auth issues).
    try {
      const [revoked] = await this.sql`
        SELECT deleted_at FROM oauth_clients
        WHERE client_id = ${clientId} AND deleted_at IS NOT NULL
      `;
      if (revoked) throw new OAuthGrantError('invalid_client', 'Client has been revoked');
    } catch (e) {
      if (e instanceof OAuthGrantError) throw e;
      if (!isUndefinedColumnError(e, 'deleted_at')) throw e;
    }
    return client;
  }

  // -------------------------------------------------------------------------
  // Client Credentials (called by custom handler, not SDK)
  // -------------------------------------------------------------------------

  /**
   * v0.37.7.0 #1166 — verify a confidential client's secret without
   * spending it. Returns the validated client info on success, throws
   * with an opaque "Invalid client" message on failure (mirrors RFC 6749
   * §5.2 invalid_client semantics). Used by the serve-http custom
   * /token handler for `authorization_code` + `refresh_token` grants on
   * confidential clients, since the SDK's plaintext compare in
   * clientAuth.js can't see our hash-only storage.
   *
   * Public clients (token_endpoint_auth_method === 'none') return
   * `client_secret_hash = NULL` from getClient; this method refuses
   * them so the SDK's PKCE path stays the canonical surface.
   */
  async verifyConfidentialClientSecret(
    clientId: string,
    presentedSecret: string,
  ): Promise<OAuthClientInformationFull> {
    // Delegate to the shared helper, but translate the typed error to
    // a plain `Error` so the auth_code + refresh_token /token handlers'
    // existing string-match dispatch in serve-http.ts keeps working
    // unchanged. New code (exchangeSubjectToken) consumes the typed
    // error directly via _authenticateConfidentialClient.
    try {
      return await this._authenticateConfidentialClient(clientId, presentedSecret);
    } catch (e) {
      if (e instanceof OAuthGrantError) throw new Error(e.message);
      throw e;
    }
  }

  async exchangeClientCredentials(
    clientId: string,
    clientSecret: string,
    requestedScope?: string,
  ): Promise<OAuthTokens> {
    const client = await this._clientsStore.getClient(clientId);
    // v0.43: typed-error migration. Was bare `throw new Error('...')` —
    // now OAuthGrantError so the cc /token handler can dispatch by code
    // the same way the token-exchange handler does. Wire descriptions
    // preserved from the pre-typed-error contract (existing tests pin
    // to these strings). RFC 6749 §5.2 codes mapped:
    //   - missing/wrong client / bad secret / revoked → invalid_client
    //   - grant_type not in client.grant_types → unauthorized_client
    if (!client) throw new OAuthGrantError('invalid_client', 'Client not found');

    // Check if client has been revoked (soft-deleted). The deleted_at column
    // is recent — pre-migration brains don't have it, so the probe must
    // tolerate that one specific failure mode without swallowing real errors
    // (lock timeouts, network blips, auth failures).
    try {
      const [revoked] = await this.sql`SELECT deleted_at FROM oauth_clients WHERE client_id = ${clientId} AND deleted_at IS NOT NULL`;
      if (revoked) throw new OAuthGrantError('invalid_client', 'Client has been revoked');
    } catch (e) {
      // F5 hardening: surface anything that ISN'T a missing-column error.
      // Bare `catch {}` masked DB outages as "client not revoked" — fail-open
      // posture in a security-sensitive code path.
      if (e instanceof OAuthGrantError) throw e;
      if (!isUndefinedColumnError(e, 'deleted_at')) throw e;
    }

    // Check grant type first (before verifying secret). RFC 6749 §5.2 —
    // unauthorized_client = "the authenticated client is not authorized
    // to use this authorization grant type."
    const grants = (client.grant_types as string[]) || [];
    if (!grants.includes('client_credentials')) {
      throw new OAuthGrantError(
        'unauthorized_client',
        'Client credentials grant not authorized for this client',
        `client.grant_types=${JSON.stringify(grants)}`,
      );
    }

    // Verify secret — constant-time hex compare (CWE-208).
    const secretHash = hashToken(clientSecret);
    if (client.client_secret === undefined || !safeHexEqual(client.client_secret, secretHash)) {
      throw new OAuthGrantError('invalid_client', 'Invalid client secret');
    }

    // Determine scopes. v0.28 swaps exact-string-match for hasScope so a
    // client whose grant is `admin` can mint tokens that include implied
    // scopes like `sources_admin` (admin implies all). Tokens are still
    // capped by what the client was registered for — this only changes how
    // the cap is computed.
    const allowedScopes = parseScopeString(client.scope);
    const requestedScopes = requestedScope ? parseScopeString(requestedScope) : allowedScopes;
    const grantedScopes = requestedScopes.filter(s => hasScope(allowedScopes, s));

    // Per-client TTL override (stored in oauth_clients.token_ttl)
    // Column may not exist on PGLite/older schemas — graceful fallback
    let clientTtl: number | undefined;
    try {
      const ttlRows = await this.sql`SELECT token_ttl FROM oauth_clients WHERE client_id = ${clientId}`;
      if (ttlRows.length > 0 && ttlRows[0].token_ttl) clientTtl = Number(ttlRows[0].token_ttl);
    } catch (e) {
      // F5 hardening: same posture as the deleted_at probe above. Only the
      // "column doesn't exist" path is a non-fatal fall-through.
      if (!isUndefinedColumnError(e, 'token_ttl')) throw e;
    }

    // Client credentials: access token only, NO refresh token (RFC 6749 4.4.3)
    return this.issueTokens(clientId, grantedScopes, undefined, false, clientTtl);
  }

  // -------------------------------------------------------------------------
  // Token Exchange (RFC 8693)
  // -------------------------------------------------------------------------

  /**
   * RFC 8693 — exchange a delegator client's credentials for an
   * access token bound to a specific end-user (subject). The calling
   * client must be registered with `token_exchange_allowed = true` AND
   * the requested subject_id must be in its `allowed_subjects` (or the
   * client is a wildcard delegator via `['*']`).
   *
   * The minted token's effective RLS scope is resolved from the subject
   * row (source_id + allowed_sources), NOT from the calling client's
   * registration — so a single delegator client serves N end-users at
   * distinct database-enforced scopes. The calling client's identity is
   * still recorded in oauth_tokens.client_id for audit ("Hermes acting
   * for subject Saad").
   *
   * Returns access-only — no refresh token. Token-exchange grants are
   * intended for short-lived per-call delegation; the calling client
   * uses its own credentials to mint fresh subject tokens as needed.
   * Per RFC 8693 §2.2.1, the response includes `issued_token_type` and
   * the scope string honors the requested_scope subset clamped against
   * the calling client's grant.
   *
   * SECURITY: this implements the "trusted upstream" pattern explicitly
   * called out by the MCP security literature (Solo.io / Microsoft Entra
   * / AWS Open Protocols). The brain trusts the delegator's assertion
   * of the subject identity ONLY because the delegator is allow-listed
   * for it — the assertion itself is unsigned. Future hardening: accept
   * a signed JWT assertion as `subject_token` when callers prefer
   * cryptographic non-repudiation over allow-list trust.
   */
  async exchangeSubjectToken(
    clientId: string,
    clientSecret: string,
    subjectToken: string,
    subjectTokenType: string,
    requestedScope?: string,
    resource?: URL,
  ): Promise<OAuthTokens & { issued_token_type: string }> {
    if (subjectTokenType !== SUBJECT_TOKEN_TYPE_SUBJECT_ID) {
      // RFC 8693 §2.2.2: unsupported subject_token_type → invalid_request.
      // Description is a fixed string; the offending value goes only to logs.
      // subjectTokenType is structural metadata (a URI we publish), NOT an
      // end-user identifier — safe to log verbatim.
      throw new OAuthGrantError(
        'invalid_request',
        'unsupported subject_token_type',
        `received subject_token_type=${JSON.stringify(subjectTokenType)}`,
      );
    }
    if (!subjectToken || typeof subjectToken !== 'string') {
      throw new OAuthGrantError('invalid_request', 'subject_token required');
    }

    // GDPR Art. 4(1) / EDPB Guidelines 01/2025: WhatsApp lids and similar
    // subject identifiers are "online identifiers" and personal data. Use
    // a SHA-256 prefix in logDetail so the raw subject_token never lands
    // in journal output via the deny-path audit log's `log_detail` field.
    // Same truncation as the allow-path `subject_id_hash` in serve-http.ts
    // → key parity across allow + deny logs.
    const subjectHashForLog = hashToken(subjectToken).slice(0, 16);

    // Resolve + authenticate via the shared confidential-client helper.
    // Throws OAuthGrantError('invalid_client', ...) on unknown client,
    // public client, wrong secret, or revoked client.
    const client = await this._authenticateConfidentialClient(clientId, clientSecret);

    // Delegation gate: the client must be explicitly opted in to
    // token-exchange AND the subject must be in its allow-list (or
    // wildcard). Defaults are off-by-default (FALSE / NULL) — a fresh
    // client registration cannot accidentally delegate.
    let delegationRows: Record<string, unknown>[];
    try {
      delegationRows = await this.sql`
        SELECT token_exchange_allowed, allowed_subjects
        FROM oauth_clients
        WHERE client_id = ${clientId}
      `;
    } catch (e) {
      // Pre-v116 brain: columns missing → delegation impossible until
      // operator runs apply-migrations. Fail closed with a server-side
      // hint kept off the wire.
      if (isUndefinedColumnError(e, 'token_exchange_allowed') || isUndefinedColumnError(e, 'allowed_subjects')) {
        throw new OAuthGrantError(
          'invalid_grant',
          'Token exchange not available on this server',
          'pre-v116 brain — operator must run gbrain apply-migrations',
        );
      }
      throw e;
    }
    if (delegationRows.length === 0 || !delegationRows[0].token_exchange_allowed) {
      // Distinct from "subject not in allow-list" so operators can tell
      // the two states apart from server logs (description on the wire
      // stays generic so we don't reveal config to the caller).
      throw new OAuthGrantError(
        'invalid_grant',
        'token exchange not authorized for this client',
        'token_exchange_allowed=false on oauth_clients row',
      );
    }
    const allowed = delegationRows[0].allowed_subjects;
    const allowedList = Array.isArray(allowed) ? (allowed as string[]) : null;
    if (allowedList === null) {
      throw new OAuthGrantError(
        'invalid_grant',
        'token exchange not authorized for this client',
        'allowed_subjects=NULL on oauth_clients row (call gbrain auth allow-exchange)',
      );
    }
    const isWildcard = allowedList.includes('*');
    if (!isWildcard && !allowedList.includes(subjectToken)) {
      throw new OAuthGrantError(
        'invalid_grant',
        'subject not allowed for this client',
        `subject_id_hash=${subjectHashForLog} not in allowed_subjects`,
      );
    }

    // Look up the subject. Must exist + not be soft-deleted.
    const subjectRows = await this.sql`
      SELECT subject_id, source_id, allowed_sources
      FROM subjects
      WHERE subject_id = ${subjectToken} AND deleted_at IS NULL
    `;
    if (subjectRows.length === 0) {
      throw new OAuthGrantError(
        'invalid_grant',
        'subject not found',
        `subject_id_hash=${subjectHashForLog} absent or soft-deleted`,
      );
    }

    // Scope clamp: requested scope filtered against the calling
    // client's registered grant. Matches the pattern used by every
    // other grant in this file (RFC 6749 §6 / §3.3).
    const allowedScopes = parseScopeString(client.scope);
    const requestedScopes = requestedScope ? parseScopeString(requestedScope) : allowedScopes;
    const grantedScopes = requestedScopes.filter(s => hasScope(allowedScopes, s));

    // Issue access-only (no refresh). Short TTL by design — defer to
    // the calling client to mint fresh tokens per turn. RFC 8707
    // `resource` is bound onto the token row so the delegator can
    // request an audience-pinned token (defense against cross-server
    // replay).
    const tokens = await this.issueTokens(
      clientId,
      grantedScopes,
      resource,
      false,
      undefined,
      subjectToken,
    );
    return {
      ...tokens,
      issued_token_type: ISSUED_TOKEN_TYPE_ACCESS,
    };
  }

  // -------------------------------------------------------------------------
  // Subject Registry (RFC 8693 — admin helpers)
  // -------------------------------------------------------------------------

  /**
   * Upsert a subject. The minimal CRUD entry point for the subject
   * registry — CLI (`gbrain auth subjects add`) and admin HTTP routes
   * call this. Subject IDs are caller-chosen opaque strings; the brain
   * treats them as keys and never parses semantic meaning, BUT we still
   * reject a few values at the boundary:
   *
   *   - `*` is the wildcard sentinel in `oauth_clients.allowed_subjects`
   *     — letting it be a real subject_id would shadow the wildcard
   *     semantics so a wildcard delegator could exchange `subject_token=*`
   *     and get the literal-* subject's scope.
   *   - whitespace + control chars break audit-log parsing and risk
   *     URL/header smuggling at downstream consumers.
   *   - empty string is meaningless and matches the falsy guard in
   *     exchangeSubjectToken (would never resolve).
   *   - length > 256 caps the index footprint on the subjects PK.
   */
  async upsertSubject(opts: {
    subjectId: string;
    displayName?: string;
    role?: string;
    sourceId?: string;
    allowedSources: string[];
  }): Promise<void> {
    const sid = opts.subjectId;
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 256) {
      throw new Error('subject_id must be a non-empty string of <= 256 chars');
    }
    if (sid === '*') {
      throw new Error('subject_id "*" is reserved (wildcard sentinel in allowed_subjects)');
    }
    // \s catches ALL whitespace (space, tab, newline); also reject control
    // chars (\x00-\x1F + \x7F) to keep audit logs / Postgres TEXT[] safe.
    // eslint-disable-next-line no-control-regex
    if (/[\s\x00-\x1F\x7F]/.test(sid)) {
      throw new Error('subject_id must not contain whitespace or control characters');
    }

    await this.sql`
      INSERT INTO subjects (subject_id, display_name, role, source_id, allowed_sources, updated_at)
      VALUES (${opts.subjectId}, ${opts.displayName ?? null}, ${opts.role ?? null},
              ${opts.sourceId ?? null}, ${pgArray(opts.allowedSources)}, now())
      ON CONFLICT (subject_id) DO UPDATE
      SET display_name = EXCLUDED.display_name,
          role = EXCLUDED.role,
          source_id = EXCLUDED.source_id,
          allowed_sources = EXCLUDED.allowed_sources,
          updated_at = now(),
          deleted_at = NULL
    `;
  }

  /**
   * Soft-delete a subject. Tokens already minted for this subject_id
   * become invalid at verifyAccessToken time (the JOIN on subjects
   * with `deleted_at IS NULL` returns zero rows → InvalidTokenError).
   * Hard-delete is left as a future explicit op so admins don't lose
   * audit history.
   */
  async deleteSubject(subjectId: string): Promise<void> {
    await this.sql`UPDATE subjects SET deleted_at = now() WHERE subject_id = ${subjectId}`;
  }

  async listSubjects(): Promise<Array<{
    subject_id: string;
    display_name: string | null;
    role: string | null;
    source_id: string | null;
    allowed_sources: string[];
  }>> {
    const rows = await this.sql`
      SELECT subject_id, display_name, role, source_id, allowed_sources
      FROM subjects
      WHERE deleted_at IS NULL
      ORDER BY subject_id
    `;
    return rows as Array<{
      subject_id: string;
      display_name: string | null;
      role: string | null;
      source_id: string | null;
      allowed_sources: string[];
    }>;
  }

  /**
   * Toggle the token-exchange delegation flag on an existing OAuth
   * client and set its allow-list. Pass `subjects: ['*']` for a
   * wildcard delegator (e.g., the multi-tenant WhatsApp gateway);
   * pass `subjects: []` to revoke delegation while leaving the client
   * otherwise intact.
   *
   * Hard cap at 10,000 entries — beyond that the per-exchange
   * `allowedList.includes(subjectToken)` becomes O(n) on a hot path
   * and a compromised admin could DoS the brain by setting a huge
   * allow-list. Operators with more than 10k subjects should be
   * using a wildcard delegator + relying on the `subjects` table
   * filter instead.
   *
   * Returns true if exactly one row was updated; false when no client
   * matched (typo path). Callers should error on false rather than
   * silently reporting success — see auth.ts allow-exchange CLI for
   * the canonical handling.
   */
  async allowClientExchange(clientId: string, subjects: string[]): Promise<boolean> {
    if (subjects.length > 10_000) {
      throw new Error('allowed_subjects exceeds maximum of 10000 entries; use a wildcard delegator instead');
    }
    const enabled = subjects.length > 0;
    const rows = await this.sql`
      UPDATE oauth_clients
      SET token_exchange_allowed = ${enabled},
          allowed_subjects = ${enabled ? pgArray(subjects) : null}
      WHERE client_id = ${clientId}
      RETURNING client_id
    `;
    return rows.length > 0;
  }

  // -------------------------------------------------------------------------
  // Maintenance
  // -------------------------------------------------------------------------

  async sweepExpiredTokens(): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    // F6 hardening: postgres.js and PGLite expose deleted-row count on
    // different shapes; `(result as any).count` returned 0 on at least one
    // engine even when rows were deleted, and codes were never counted at
    // all. RETURNING 1 + array length is portable across both engines.
    const result = await this.sql`
      DELETE FROM oauth_tokens WHERE expires_at < ${now} RETURNING 1
    `;
    const deletedCodes = await this.sql`
      DELETE FROM oauth_codes WHERE expires_at < ${now} RETURNING 1
    `;
    return result.length + deletedCodes.length;
  }

  // -------------------------------------------------------------------------
  // CLI Registration Helper
  // -------------------------------------------------------------------------

  async registerClientManual(
    name: string,
    grantTypes: string[],
    scopes: string,
    redirectUris: string[] = [],
    sourceId: string = 'default',
    federatedRead?: string[],
    tokenEndpointAuthMethod?: string,
  ): Promise<{ clientId: string; clientSecret?: string }> {
    // v0.28: ALLOWED_SCOPES allowlist. Reject `--scopes "read flying-unicorn"`
    // at registration so meaningless scope strings can't pile up in the DB.
    // Pre-allowlist clients keep working (allowlist is registration-time;
    // existing rows aren't re-validated).
    assertAllowedScopes(parseScopeString(scopes));

    // v0.41.3 (T1+T2): validate token_endpoint_auth_method at the registration
    // boundary. Throws InvalidTokenEndpointAuthMethodError on bad input.
    // Default is `client_secret_post` (RFC 7591 §2).
    const authMethod = validateTokenEndpointAuthMethod(tokenEndpointAuthMethod);

    const clientId = generateToken('gbrain_cl_');
    // v0.41.3 (T2): atomic public-client INSERT. When the caller declares
    // `tokenEndpointAuthMethod: 'none'` we mint NO secret and INSERT with
    // client_secret_hash = NULL in a single statement. Pre-fix, the admin
    // endpoint did INSERT-then-UPDATE which left a confidential row stranded
    // if the UPDATE failed mid-flight (codex F4). Confidential clients
    // (`client_secret_post` / `client_secret_basic`) get the secret minted
    // and hashed as before.
    const isPublicClient = authMethod === 'none';
    const clientSecret = isPublicClient ? undefined : generateToken('gbrain_cs_');
    const secretHash = clientSecret ? hashToken(clientSecret) : null;
    const now = Math.floor(Date.now() / 1000);

    // v0.34.1 (#861 + #876): persist source_id AND federated_read so
    // verifyAccessToken can populate both AuthInfo fields. Defaults:
    //   source_id = 'default' (matches v60 backfill)
    //   federated_read = [source_id] when omitted (a non-federated client
    //                    has read scope == write scope, the v0.33 default)
    const federated = federatedRead && federatedRead.length > 0 ? federatedRead : [sourceId];
    try {
      await this.sql`
        INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                    grant_types, scope, token_endpoint_auth_method,
                                    client_id_issued_at,
                                    source_id, federated_read)
        VALUES (${clientId}, ${secretHash}, ${name},
                ${pgArray(redirectUris)}, ${pgArray(grantTypes)}, ${scopes}, ${authMethod}, ${now},
                ${sourceId}, ${pgArray(federated)})
      `;
    } catch (err) {
      // Pre-v60 / pre-v61 brain: column missing. Fall back through both
      // projections so registration still works until apply-migrations.
      if (isUndefinedColumnError(err, 'federated_read')) {
        // v60-only brain: source_id but no federated_read.
        try {
          await this.sql`
            INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                        grant_types, scope, token_endpoint_auth_method,
                                        client_id_issued_at, source_id)
            VALUES (${clientId}, ${secretHash}, ${name},
                    ${pgArray(redirectUris)}, ${pgArray(grantTypes)}, ${scopes}, ${authMethod}, ${now}, ${sourceId})
          `;
        } catch (err2) {
          if (isUndefinedColumnError(err2, 'source_id')) {
            await this.sql`
              INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                          grant_types, scope, token_endpoint_auth_method,
                                          client_id_issued_at)
              VALUES (${clientId}, ${secretHash}, ${name},
                      ${pgArray(redirectUris)}, ${pgArray(grantTypes)}, ${scopes}, ${authMethod}, ${now})
            `;
          } else {
            throw err2;
          }
        }
      } else if (isUndefinedColumnError(err, 'source_id')) {
        await this.sql`
          INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
                                      grant_types, scope, token_endpoint_auth_method,
                                      client_id_issued_at)
          VALUES (${clientId}, ${secretHash}, ${name},
                  ${pgArray(redirectUris)}, ${pgArray(grantTypes)}, ${scopes}, ${authMethod}, ${now})
        `;
      } else {
        throw err;
      }
    }

    return { clientId, clientSecret };
  }

  // -------------------------------------------------------------------------
  // Internal: Issue access + optional refresh tokens
  // -------------------------------------------------------------------------

  private async issueTokens(
    clientId: string,
    scopes: string[],
    resource: URL | undefined,
    includeRefresh: boolean,
    ttlOverride?: number,
    subjectId?: string,
  ): Promise<OAuthTokens> {
    const accessToken = generateToken('gbrain_at_');
    const accessHash = hashToken(accessToken);
    const now = Math.floor(Date.now() / 1000);
    const effectiveTtl = ttlOverride || this.tokenTtl;
    const accessExpiry = now + effectiveTtl;

    // RFC 8693 (v117): persist subject_id on the access row when this
    // is a token-exchange grant. verifyAccessToken keys off this column
    // to resolve the subject's RLS scope at lookup time. Pre-v117 brain
    // → INSERT fails on the unknown column → fall back to the legacy
    // INSERT and skip the subject binding (the calling client's static
    // scope applies, mirroring pre-RFC8693 behavior).
    try {
      await this.sql`
        INSERT INTO oauth_tokens (token_hash, token_type, client_id, scopes, expires_at, resource, subject_id)
        VALUES (${accessHash}, ${'access'}, ${clientId},
                ${pgArray(scopes)}, ${accessExpiry}, ${resource?.toString() || null},
                ${subjectId ?? null})
      `;
    } catch (err) {
      if (subjectId !== undefined) throw err;
      if (!isUndefinedColumnError(err, 'subject_id')) throw err;
      await this.sql`
        INSERT INTO oauth_tokens (token_hash, token_type, client_id, scopes, expires_at, resource)
        VALUES (${accessHash}, ${'access'}, ${clientId},
                ${pgArray(scopes)}, ${accessExpiry}, ${resource?.toString() || null})
      `;
    }

    const result: OAuthTokens = {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: effectiveTtl,
      scope: scopes.join(' '),
    };

    if (includeRefresh) {
      const refreshToken = generateToken('gbrain_rt_');
      const refreshHash = hashToken(refreshToken);
      const refreshExpiry = now + this.refreshTtl;

      // Refresh rows never carry subject_id — token-exchange grants
      // are access-only by design (see exchangeSubjectToken docstring).
      // If a non-exchange grant is somehow refresh-issued with subjectId
      // set, the value silently drops here; that's a caller bug we don't
      // mask. The pre-v117 fallback applies only to the access INSERT.
      await this.sql`
        INSERT INTO oauth_tokens (token_hash, token_type, client_id, scopes, expires_at, resource)
        VALUES (${refreshHash}, ${'refresh'}, ${clientId},
                ${pgArray(scopes)}, ${refreshExpiry}, ${resource?.toString() || null})
      `;

      result.refresh_token = refreshToken;
    }

    return result;
  }
}
