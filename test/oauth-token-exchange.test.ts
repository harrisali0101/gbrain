import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite/vector';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import {
  GBrainOAuthProvider,
  SUBJECT_TOKEN_TYPE_SUBJECT_ID,
  ISSUED_TOKEN_TYPE_ACCESS,
  OAuthGrantError,
} from '../src/core/oauth-provider.ts';
import { PGLITE_SCHEMA_SQL } from '../src/core/pglite-schema.ts';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

// ---------------------------------------------------------------------------
// RFC 8693 token-exchange suite
//
// Covers:
//   - happy path: delegator client mints subject-scoped access token
//   - issued_token_type set per RFC 8693 §2.2.1
//   - verifyAccessToken resolves subject's source_id + allowedSources
//     (NOT the calling client's) on tokens minted via this grant
//   - denial paths: client not allow-listed, subject not in client's list,
//     unknown subject, soft-deleted subject, unsupported subject_token_type,
//     wrong client secret, refresh token NOT issued for this grant
//   - access tokens minted via plain client_credentials still use the
//     calling client's source_id / federated_read (regression guard)
// ---------------------------------------------------------------------------

let db: PGlite;
let sql: (strings: TemplateStringsArray, ...values: unknown[]) => Promise<any>;
let provider: GBrainOAuthProvider;

beforeAll(async () => {
  db = new PGlite({ extensions: { vector, pg_trgm } });
  await db.exec(PGLITE_SCHEMA_SQL);
  sql = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const query = strings.reduce((acc, str, i) => acc + str + (i < values.length ? `$${i + 1}` : ''), '');
    const result = await db.query(query, values as any[]);
    return result.rows;
  };
  provider = new GBrainOAuthProvider({ sql, tokenTtl: 60, refreshTtl: 300 });
  // The default source the fixtures reference. pglite-schema.ts seeds it
  // already, but we re-assert to keep the test self-contained.
  await sql`INSERT INTO sources (id, name) VALUES ('default', 'default') ON CONFLICT (id) DO NOTHING`;
  await sql`INSERT INTO sources (id, name) VALUES ('general', 'general') ON CONFLICT (id) DO NOTHING`;
  await sql`INSERT INTO sources (id, name) VALUES ('leadership', 'leadership') ON CONFLICT (id) DO NOTHING`;
  await sql`INSERT INTO sources (id, name) VALUES ('finance', 'finance') ON CONFLICT (id) DO NOTHING`;
}, 30_000);

beforeEach(async () => {
  // Each test owns its own clients and subjects; wipe between runs so
  // a leftover wildcard client from one test can't grant access in
  // another. Tokens cascade via FK.
  await sql`DELETE FROM oauth_tokens`;
  await sql`DELETE FROM oauth_clients`;
  await sql`DELETE FROM subjects`;
});

afterAll(async () => {
  if (db) await db.close();
}, 15_000);

// Helper: register a delegator client with our standard scopes.
async function registerDelegator(opts: {
  name?: string;
  scopes?: string;
  allowedSubjects: string[] | null;
}): Promise<{ clientId: string; clientSecret: string }> {
  const { clientId, clientSecret } = await provider.registerClientManual(
    opts.name ?? 'hermes-delegator',
    ['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange'],
    opts.scopes ?? 'read',
    [],
    'default',
    ['default'],
  );
  if (!clientSecret) throw new Error('delegator must be confidential');
  if (opts.allowedSubjects !== null) {
    await provider.allowClientExchange(clientId, opts.allowedSubjects);
  }
  return { clientId, clientSecret };
}

describe('exchangeSubjectToken — happy path', () => {
  test('mints an access token bound to the subject, with subject-scoped RLS', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['saad@lid'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid',
      displayName: 'Saad',
      role: 'super_admin',
      sourceId: 'general',
      allowedSources: ['general', 'leadership', 'finance'],
    });

    const tokens = await provider.exchangeSubjectToken(
      clientId,
      clientSecret,
      'saad@lid',
      SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    );

    expect(tokens.access_token).toBeDefined();
    expect(tokens.access_token).toStartWith('gbrain_at_');
    expect(tokens.token_type).toBe('bearer');
    expect(tokens.issued_token_type).toBe(ISSUED_TOKEN_TYPE_ACCESS);
    expect(tokens.refresh_token).toBeUndefined();   // §C: no refresh for exchange grants
    expect(tokens.expires_in).toBe(60);

    // verifyAccessToken must resolve the subject's source / allowed_sources,
    // NOT the delegator's. This is the load-bearing assertion.
    const auth = await provider.verifyAccessToken(tokens.access_token);
    expect(auth.clientId).toBe(clientId);                       // delegator preserved
    expect((auth as any).subjectId).toBe('saad@lid');           // audit trail
    expect((auth as any).sourceId).toBe('general');             // FROM SUBJECT
    expect((auth as any).allowedSources).toEqual(['general', 'leadership', 'finance']);
  });

  test('wildcard delegator accepts any subject', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({
      subjectId: 'anyone@lid',
      sourceId: 'general',
      allowedSources: ['general'],
    });
    const tokens = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'anyone@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    );
    const auth = await provider.verifyAccessToken(tokens.access_token);
    expect((auth as any).subjectId).toBe('anyone@lid');
  });

  test('scope clamp: requested scope outside client grant is dropped', async () => {
    const { clientId, clientSecret } = await registerDelegator({
      scopes: 'read',  // delegator only has read
      allowedSubjects: ['saad@lid'],
    });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    const tokens = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID, 'read write admin',
    );
    expect(tokens.scope).toBe('read');               // write/admin filtered out
  });
});

describe('exchangeSubjectToken — denial paths', () => {
  test('client not allow-listed for exchange (token_exchange_allowed=FALSE) → invalid_grant', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: null });
    // Subject exists, but client never had allowClientExchange called.
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    expect(provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    )).rejects.toThrow(/not authorized for token exchange/);
  });

  test('subject not in client allow-list → rejected even though it exists in subjects table', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['only-saad@lid'] });
    await provider.upsertSubject({
      subjectId: 'shahzaib@lid', sourceId: 'general', allowedSources: ['general'],
    });
    // Wire-safe error description is a FIXED lowercase string — caller
    // input is never echoed onto the wire. The verbose context (which
    // subject was rejected) lives in OAuthGrantError.logDetail.
    expect(provider.exchangeSubjectToken(
      clientId, clientSecret, 'shahzaib@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    )).rejects.toThrow(/subject not allowed for this client/);
  });

  test('subject does not exist → rejected', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    expect(provider.exchangeSubjectToken(
      clientId, clientSecret, 'ghost@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    )).rejects.toThrow(/subject not found/);
  });

  test('soft-deleted subject is unknown to exchange', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    await provider.deleteSubject('saad@lid');
    expect(provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    )).rejects.toThrow(/subject not found/);
  });

  test('soft-deleted subject also fails verifyAccessToken on tokens already minted', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    const tokens = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    );
    // Token validates pre-deletion.
    await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toBeDefined();
    await provider.deleteSubject('saad@lid');
    // Same token now fails — load-bearing: a compromised delegator cannot
    // keep using stale subject tokens for revoked end-users.
    expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(InvalidTokenError);
  });

  test('unsupported subject_token_type → invalid_request', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    expect(provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', 'urn:ietf:params:oauth:token-type:jwt',
    )).rejects.toThrow(/unsupported subject_token_type/);
  });

  test('wrong client secret → invalid_client', async () => {
    const { clientId } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    expect(provider.exchangeSubjectToken(
      clientId, 'gbrain_cs_wrong', 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    )).rejects.toThrow(/Invalid client/);
  });
});

describe('regression: non-exchange grants still use the client\'s source / federated_read', () => {
  test('client_credentials grant returns client-scoped AuthInfo (NOT subject-scoped)', async () => {
    const { clientId, clientSecret } = await provider.registerClientManual(
      'plain-client',
      ['client_credentials'],
      'read',
      [],
      'leadership',
      ['leadership'],
    );
    if (!clientSecret) throw new Error('confidential client expected');
    const tokens = await provider.exchangeClientCredentials(clientId, clientSecret);
    const auth = await provider.verifyAccessToken(tokens.access_token);
    expect((auth as any).sourceId).toBe('leadership');
    expect((auth as any).allowedSources).toEqual(['leadership']);
    expect((auth as any).subjectId).toBeUndefined();
  });
});

describe('allowClientExchange', () => {
  test('passing --revoke equivalent (empty array) sets token_exchange_allowed=FALSE', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['saad@lid'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    // Works once.
    await provider.exchangeSubjectToken(clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID);
    // Now revoke; future calls fail.
    await provider.allowClientExchange(clientId, []);
    expect(provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    )).rejects.toThrow(/not authorized for token exchange/);
  });
});

describe('listSubjects', () => {
  test('returns only non-deleted subjects, sorted by id', async () => {
    await provider.upsertSubject({ subjectId: 'b@lid', sourceId: 'general', allowedSources: ['general'] });
    await provider.upsertSubject({ subjectId: 'a@lid', sourceId: 'general', allowedSources: ['general'] });
    await provider.upsertSubject({ subjectId: 'c@lid', sourceId: 'general', allowedSources: ['general'] });
    await provider.deleteSubject('b@lid');
    const rows = await provider.listSubjects();
    expect(rows.map(r => r.subject_id)).toEqual(['a@lid', 'c@lid']);
  });
});

describe('subject_id format validation (boundary hardening)', () => {
  test('rejects literal "*" — would shadow the wildcard sentinel', async () => {
    await expect(provider.upsertSubject({
      subjectId: '*', sourceId: 'general', allowedSources: ['general'],
    })).rejects.toThrow(/reserved/);
  });

  test('rejects empty string', async () => {
    await expect(provider.upsertSubject({
      subjectId: '', sourceId: 'general', allowedSources: ['general'],
    })).rejects.toThrow(/non-empty/);
  });

  test('rejects whitespace + control chars', async () => {
    await expect(provider.upsertSubject({
      subjectId: 'foo bar', sourceId: 'general', allowedSources: ['general'],
    })).rejects.toThrow(/whitespace or control/);
    await expect(provider.upsertSubject({
      subjectId: 'foo\tbar', sourceId: 'general', allowedSources: ['general'],
    })).rejects.toThrow(/whitespace or control/);
    await expect(provider.upsertSubject({
      subjectId: 'foo\x00bar', sourceId: 'general', allowedSources: ['general'],
    })).rejects.toThrow(/whitespace or control/);
  });

  test('rejects length > 256', async () => {
    const huge = 'a'.repeat(257) + '@lid';
    await expect(provider.upsertSubject({
      subjectId: huge, sourceId: 'general', allowedSources: ['general'],
    })).rejects.toThrow(/<= 256/);
  });

  test('accepts the WhatsApp lid format used in the pilot', async () => {
    // Sanity — the validation must not break the documented happy path.
    await expect(provider.upsertSubject({
      subjectId: '87449845936164@lid', sourceId: 'general', allowedSources: ['general'],
    })).resolves.toBeUndefined();
  });
});

describe('allowClientExchange — size cap on allowed_subjects', () => {
  test('rejects an allow-list larger than 10000 entries (DoS mitigation)', async () => {
    const { clientId } = await registerDelegator({ allowedSubjects: ['placeholder@lid'] });
    const bigList = Array.from({ length: 10_001 }, (_, i) => `sub${i}@lid`);
    await expect(provider.allowClientExchange(clientId, bigList))
      .rejects.toThrow(/exceeds maximum/);
  });

  test('accepts exactly 10000 entries (boundary)', async () => {
    const { clientId } = await registerDelegator({ allowedSubjects: ['placeholder@lid'] });
    const boundaryList = Array.from({ length: 10_000 }, (_, i) => `sub${i}@lid`);
    await expect(provider.allowClientExchange(clientId, boundaryList))
      .resolves.toBe(true);
  });
});

describe('scope echo (RFC 8693 §2.2.1)', () => {
  test('response includes a `scope` field always, populated with the EFFECTIVE granted scopes', async () => {
    const { clientId, clientSecret } = await registerDelegator({
      scopes: 'read write',
      allowedSubjects: ['saad@lid'],
    });
    await provider.upsertSubject({ subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'] });

    // requested = ['read'] → granted = ['read'] (subset of grant)
    const r1 = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID, 'read',
    );
    expect(r1.scope).toBe('read');

    // requested omitted → granted defaults to full client grant
    const r2 = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    );
    expect(r2.scope?.split(' ').sort()).toEqual(['read', 'write']);

    // requested superset → clamped DOWN; response echoes the narrower set
    const r3 = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID, 'read write admin',
    );
    expect(r3.scope?.split(' ').sort()).toEqual(['read', 'write']);   // admin dropped
  });
});

describe('RFC 8707 resource binding', () => {
  test('exchange honors `resource` parameter and persists it on the token row', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['saad@lid'] });
    await provider.upsertSubject({ subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'] });
    const resource = new URL('https://hermes.example.com/mcp');
    const tokens = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID, undefined, resource,
    );
    const auth = await provider.verifyAccessToken(tokens.access_token);
    // verifyAccessToken returns a URL when oauth_tokens.resource is set;
    // the value round-trips through Postgres TEXT verbatim.
    expect(auth.resource).toBeDefined();
    expect(auth.resource?.toString()).toBe(resource.toString());
  });

  test('exchange without resource leaves the token unbound (back-compat)', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['saad@lid'] });
    await provider.upsertSubject({ subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'] });
    const tokens = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    );
    const auth = await provider.verifyAccessToken(tokens.access_token);
    expect(auth.resource).toBeUndefined();
  });
});

describe('typed OAuth errors carry safe-for-wire descriptions', () => {
  test('rejects with code+description; logDetail carries HASHED subject (no plaintext lid in logs)', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['only-saad@lid'] });
    await provider.upsertSubject({
      subjectId: 'shahzaib@lid', sourceId: 'general', allowedSources: ['general'],
    });
    try {
      await provider.exchangeSubjectToken(
        clientId, clientSecret, 'shahzaib@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
      );
      throw new Error('expected throw');
    } catch (e) {
      // Must be the typed class so the wire-boundary dispatch is exhaustive
      // at the type level — not brittle string-match on err.message.
      expect(e).toBeInstanceOf(OAuthGrantError);
      const oerr = e as OAuthGrantError;
      expect(oerr.code).toBe('invalid_grant');
      // The wire-safe description is a FIXED string with no input echo.
      expect(oerr.message).toBe('subject not allowed for this client');
      expect(oerr.message).not.toContain('shahzaib');
      // GDPR / EDPB Guidelines 01/2025: the WhatsApp lid is an "online
      // identifier" — load-bearing: logDetail must carry the SHA-256
      // PREFIX, NOT the raw lid, so the deny-path audit log doesn't leak
      // PII into journald via OAuthGrantError.logDetail.
      expect(oerr.logDetail).not.toContain('shahzaib');
      expect(oerr.logDetail).toMatch(/subject_id_hash=[0-9a-f]{16}/);
    }
  });

  test('unsupported subject_token_type echoes the URI (structural metadata, not PII)', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({ subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'] });
    try {
      await provider.exchangeSubjectToken(
        clientId, clientSecret, 'saad@lid',
        'urn:ietf:params:oauth:token-type:jwt',  // not supported
      );
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(OAuthGrantError);
      const oerr = e as OAuthGrantError;
      expect(oerr.code).toBe('invalid_request');
      expect(oerr.message).toBe('unsupported subject_token_type');
      expect(oerr.message).not.toContain('jwt');
      // The URI is a published value (server advertises which subject_token_types
      // it accepts), NOT an end-user identifier — safe to log verbatim.
      expect(oerr.logDetail).toContain('jwt');
    }
  });
});

describe('regression: pre-v117 issueTokens fallback', () => {
  test('client_credentials grant still issues a working access token after v117 columns exist', async () => {
    // v117 added oauth_tokens.subject_id; issueTokens INSERTs that column
    // when present and falls back to the pre-v117 column set otherwise.
    // This test asserts the non-fallback path (PGLite seeds the full schema)
    // remains correct end-to-end — guards against a typo where the new
    // subject_id INSERT path could break the non-subject grants.
    const { clientId, clientSecret } = await provider.registerClientManual(
      'plain-cc-client',
      ['client_credentials'],
      'read',
      [],
      'general',
      ['general'],
    );
    if (!clientSecret) throw new Error('confidential client expected');
    const tokens = await provider.exchangeClientCredentials(clientId, clientSecret);
    const auth = await provider.verifyAccessToken(tokens.access_token);
    expect(auth.clientId).toBe(clientId);
    expect((auth as any).subjectId).toBeUndefined();
    expect(tokens.refresh_token).toBeUndefined();   // cc grants don't refresh
  });
});

describe('race: deleteSubject mid-exchange does not produce a working token', () => {
  test('subject deleted between mint and verify → InvalidTokenError', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    // Two operations that race in production: the gateway exchanges a
    // token for saad; an operator concurrently revokes saad. We simulate
    // by running deleteSubject AFTER exchange completes but BEFORE the
    // gateway uses the token — the same wall-clock outcome as a real race.
    const tokens = await provider.exchangeSubjectToken(
      clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID,
    );
    await provider.deleteSubject('saad@lid');
    // verifyAccessToken JOINs subjects with deleted_at IS NULL → 0 rows
    // → throws InvalidTokenError. Load-bearing: this is the only barrier
    // between a compromised delegator and an indefinitely-replayable
    // subject token. If this test ever starts passing instead of throwing,
    // the soft-delete revocation guarantee is gone.
    await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow();
  });

  test('concurrent exchange + deleteSubject — even when delete races BEFORE the exchange completes, the token must not be usable', async () => {
    const { clientId, clientSecret } = await registerDelegator({ allowedSubjects: ['*'] });
    await provider.upsertSubject({
      subjectId: 'saad@lid', sourceId: 'general', allowedSources: ['general'],
    });
    // Fire both at once. We don't assert which wins (it's a true race)
    // but we DO assert that any token we successfully obtained still
    // fails verify after the delete settles. Belt-and-suspenders for
    // the "delegator can use stale subject tokens" hazard.
    const [exchangeResult, _del] = await Promise.allSettled([
      provider.exchangeSubjectToken(clientId, clientSecret, 'saad@lid', SUBJECT_TOKEN_TYPE_SUBJECT_ID),
      provider.deleteSubject('saad@lid'),
    ]);
    if (exchangeResult.status === 'fulfilled') {
      await expect(provider.verifyAccessToken(exchangeResult.value.access_token)).rejects.toThrow();
    }
  });
});
