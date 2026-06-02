# Debunked Security Findings

False-positive / non-actionable reports identified during security triage of Apache Superset.
Each was investigated against the actual code; none required a fix. Finding IDs are reused
across separate report batches, so items are grouped by topic and annotated with the source
report.

> **Legend** — **FALSE POSITIVE**: the described vulnerability does not exist. **NON-ISSUE**:
> the observation is literally true but has no security impact (working as intended /
> already mitigated).

## Summary

| # | Topic | Source finding(s) | Verdict |
|---|-------|-------------------|---------|
| 1 | Frontend hooks "missing column specification" | column-spec cluster (`15.3.1.md`) | FALSE POSITIVE |
| 2 | SSH tunnel credentials unmasked in read endpoints | SSH read endpoints (`15.3.1.md`) | FALSE POSITIVE |
| 3 | SSH tunnel raw `.data` exposes internal fields | SSH read endpoints (`15.3.1.md`) | FALSE POSITIVE |
| 4 | `get_updated_since` `to_dict()` over-exposure | queries API (`15.3.1.md`) | FALSE POSITIVE |
| 5 | CSRF-exempt endpoints lack Content-Type/header enforcement | CSRF (`3.5.2.md`) | NON-ISSUE |
| 6 | `sanitize_clause()` MySQL dialect fallback | SQL parse (`1.2.4.md`) | FALSE POSITIVE |
| 7 | `getattr` post-processing dynamic dispatch | `query_object.py` (`1.3.2.md`) | FALSE POSITIVE |
| 8 | MCP JWT verifier (algorithm / `none` / `jku` / `exp`-`nbf`) | `jwt_verifier.py` (`9.1.x`, `9.2.1`) | FALSE POSITIVE |
| 9 | `get_datasource_by_id` no access check | `commands/utils.py` (`8.2.2.md`) | FALSE POSITIVE |
| 10 | Chart screenshot missing `X-Content-Type-Options` | `charts/api.py` (`3.2.1.md`) | FALSE POSITIVE |
| 11 | Import/extension ZIP missing `check_is_safe_zip` | import/extension (`5.2.1`, `5.3.2`) | FALSE POSITIVE |
| 12 | `uuid3`/MD5 used for cache key | `metastore_cache.py` (`11.4.1.md`) | FALSE POSITIVE |
| 13 | No startup cipher-mode (AEAD) validation | `encrypt.py` (`11.3.2.md`) | NON-ISSUE |
| 14 | Legacy DB URI validator missing safety check | `views/database/validators.py` (`2.2.1.md`) | FALSE POSITIVE (dead code) |
| 15 | `row_limit` missing upper bound | `charts/schemas.py` (`2.2.1.md`) | FALSE POSITIVE |
| 16 | Authentication rate limiting not active by default | `security/manager.py` (`6.3.1.md`) | FALSE POSITIVE |
| 17 | Malicious account lockout via deliberate failed logins | `security/manager.py` (`6.3.1.md`) | FALSE POSITIVE |

---

## 1. Frontend hooks return data "without column specification"

**Reports:** `useDashboardCharts`, `useDatasetDrillInfo`, `useEmbeddedDashboard`, `queryApi`
generic base query (ASVS 15.3.1, CWE-200).

**Claim:** these hooks request full objects without a `columns` projection (unlike `useDashboard`),
over-exposing fields.

**Verdict — FALSE POSITIVE.** Field exposure in Superset is enforced **server-side** by marshmallow
schemas; the frontend `columns` param is only a bandwidth optimization, and **only the generic
`/dashboard/{id}` GET accepts it.** The flagged hooks call dedicated sub-resource endpoints that do
not accept a `columns` param and already return curated, minimal schemas:

- `useDashboardCharts` → `GET /dashboard/{id}/charts` (`superset/dashboards/api.py:641`) dumps a fixed
  `ChartEntityResponseSchema` (10 curated fields).
- `useDatasetDrillInfo` → `GET /dataset/{id}/drill_info/` (`superset/datasets/api.py:1263`) already
  restricts to a hard-coded `drill_info_select_columns` allowlist (`api.py:1307`). The claim "the full
  dataset response is stored and cached" is factually incorrect.
- `useEmbeddedDashboard` → `GET /dashboard/{id}/embedded` returns `EmbeddedDashboardResponseSchema` — 5
  fields (`uuid`, `allowed_domains`, `dashboard_id`, `changed_on`, `changed_by`), nothing sensitive.
- `queryApi` (`superset/hooks/apiResources/queryApi.ts`) is a generic RTK-Query transport that passes
  data through unless a per-endpoint `transformResponse` is set — standard behavior; it has no
  knowledge of endpoint schemas, so a "default field-limiting mechanism" is architecturally
  meaningless. Field exposure belongs server-side, where it already lives.

The proposed remediation (add a `columns` spec to the hook) would be dead query-string the backend
silently ignores. Reporter self-downgraded all to "Low — no trust boundary violation."

## 2. SSH tunnel credentials returned unmasked in read endpoints

**Report:** `get_connection()` / `get()` in `superset/databases/api.py` return SSH tunnel data
without `mask_password_info()` (ASVS 15.3.1, CWE-200) — labeled **High**.

**Verdict — FALSE POSITIVE.** The read endpoints add `database.ssh_tunnel.data`, and the
`SSHTunnel.data` property (`superset/databases/ssh_tunnel/models.py:88-102`) **already masks**
`password`, `private_key`, and `private_key_password` with `PASSWORD_MASK` before returning. It emits
only `id`, `server_address`, `server_port`, `username` plus masked placeholders. No plaintext secret is
ever returned. `post()`/`put()` use `mask_password_info()` only because they build the response from
the raw request body, not the model. The existing test
`test_get_database_returns_related_ssh_tunnel` already asserts masked output on read.

## 3. SSH tunnel data appended outside schema serialization (internal-field exposure)

**Report:** read endpoints use the raw `.data` property, "exposing internal model fields beyond the
API contract" (ASVS 15.3.1, CWE-200).

**Verdict — FALSE POSITIVE.** `SSHTunnel.data` is itself a hand-curated allowlist (see #2). It does
**not** emit `database_id`, audit columns, or any other internal field — only the four public fields
and masked credential placeholders. There is no internal-field leakage.

## 4. `get_updated_since` bypasses schema via `to_dict()`

**Report:** `superset/queries/api.py` `get_updated_since` uses `q.to_dict()` instead of the declared
`list_model_schema`, exposing all `Query` fields (ASVS 15.3.1, CWE-200).

**Verdict — FALSE POSITIVE (as a vulnerability).** The endpoint and DAO
(`QueryDAO.get_queries_changed_after`) hard-filter on `Query.user_id == get_user_id()` — it returns
**only the caller's own queries**, so this is self-exposure of a few extra fields about one's own
queries (e.g. `resultsKey`, `extra`), not cross-user disclosure. Furthermore the proposed fix
(`schema.dump()`) would **break SQL Lab**: `to_dict()` emits a camelCase shape the frontend depends on,
and `test_get_updated_since` asserts that exact shape. Low value, real regression risk.

## 5. CSRF-exempt endpoints lack Content-Type / custom-header enforcement

**Report:** CSRF-exempt endpoints rely on CORS preflight without explicit Content-Type validation
(ASVS 3.5.2).

**Verdict — NON-ISSUE.** The effective control is present and appropriate: `SESSION_COOKIE_SAMESITE =
"Lax"` (`superset/config.py`) already blocks cross-site cookie-bearing POSTs to the JSON endpoints. The
report concedes this and proposes only vague defense-in-depth; adding per-endpoint Content-Type
enforcement to public APIs (some accept form-encoded bodies) risks regressions for no real gain. (The
report also cites the wrong config lines — the CSRF block is `WTF_CSRF_EXEMPT_LIST`, not the
`SQLALCHEMY_ENGINE_OPTIONS` lines referenced.)

## 6. `sanitize_clause()` MySQL dialect fallback parser-differential

**Report:** `superset/sql/parse.py` falls back to the MySQL dialect when an unknown engine's SQL with
backticks fails to parse, creating a parser-differential risk (ASVS 1.2.4, CWE-436).

**Verdict — FALSE POSITIVE.** The fallback only changes which **identifier-quoting grammar** is used to
parse; it does **not** relax the single-statement / balanced-expression invariant that provides the
actual injection protection (a multi-statement payload still parses to >1 statement and is rejected).
It fires only for unknown/base dialects (where there was no correct dialect anyway) and only when a
literal backtick is present. It was added deliberately (PR #36545) to support "Other"-type databases
with MySQL-style backtick identifiers. The clause input is operator-controlled (requires
SQL-in-adhoc-filter permission). No bypass.

## 7. `getattr` dynamic dispatch in post-processing

**Reports:** `exec_post_processing()` in `superset/common/query_object.py` uses
`getattr(pandas_postprocessing, operation)` guarded only by `hasattr` (ASVS 1.3.2, CWE-470). *(Raised
twice — `1.3.2.md`.)*

**Verdict — FALSE POSITIVE.** The `operation` name is **already allowlisted upstream** by the
marshmallow schema: `ChartDataPostProcessingOperationSchema.operation` uses
`validate.OneOf(choices=[functions of pandas_postprocessing])` (`superset/charts/schemas.py`). The
module namespace contains no dangerous callables (`pd`, `DataFrame`, builtins are not imported there);
the only reachable "extra" attributes are two harmless string helpers. A user cannot invoke an
unintended callable. `hasattr` is not the only guard.

## 8. MCP JWT verifier hardening (algorithm / `none` / `jku`-`x5u`-`jwk` / `exp`-`nbf`)

**Reports:** `superset/mcp_service/jwt_verifier.py` — conditional algorithm check, no explicit `alg:
none` rejection, no stripping of `jku`/`x5u`/`jwk` headers, and no `exp`/`nbf` enforcement (ASVS 9.1.1,
9.1.2, 9.1.3, 9.2.1). *(Raised across multiple batches.)*

**Verdict — FALSE POSITIVE.** `DetailedJWTVerifier` delegates real verification to authlib's
`JsonWebToken([self.algorithm])` via `self.jwt.decode(...)`:

- **Algorithm:** `self.algorithm` is always set by the sole factory (`mcp_config.py`, hardcoded
  `HS256` or `MCP_JWT_ALGORITHM` defaulting to `RS256`); authlib independently rejects any algorithm
  not in its single-element allowlist — including `none`.
- **`jku`/`x5u`/`jwk`:** `_get_verification_key()` resolves keys **only** from the pre-configured static
  public key or the operator-configured JWKS URI; only `kid` is read from the token header and it can't
  point outside the configured JWKS. Token headers cannot influence key resolution.
- **`exp`/`nbf`:** authlib validates registered time claims during `decode()`; an expired or
  not-yet-valid token is rejected.

The explicit checks the reports request are redundant with authlib (defense-in-depth at most), not
closing a real hole. (A separate, *valid* concern — tokens minted **without** an `exp` claim — is
about token *issuance*, addressed in PR #40651, not the verifier.)

## 9. `get_datasource_by_id` returns data without access verification

**Report:** `superset/commands/utils.py` `get_datasource_by_id` performs no access check; proposed
`check_access=True` default (ASVS 8.2.2).

**Verdict — FALSE POSITIVE (for the proposed default-on fix).** The function has two callers
(`CreateChartCommand.validate`, `UpdateChartCommand.validate`), both of which only read
`datasource.name`; datasource authorization for chart create/update is enforced elsewhere in the chart
API flow. Flipping `check_access=True` by default would inject a new authorization gate into those
paths with no demonstrated vulnerability (the report itself states "no evidence of exploitable paths").
If hardened at all, it should be an opt-in parameter defaulting to `False` to preserve behavior.

## 10. Chart screenshot/thumbnail endpoints missing `X-Content-Type-Options: nosniff`

**Report:** `superset/charts/api.py` image endpoints lack a `nosniff` header (ASVS 3.2.1, CWE-116).

**Verdict — FALSE POSITIVE.** Flask-Talisman is initialized globally (`TALISMAN_ENABLED` defaults
`True`) and its default `x_content_type_options=True` adds `X-Content-Type-Options: nosniff` to **every**
response via an `after_request` hook. The header is already present on the image responses. A
per-endpoint header would be redundant.

## 11. Import / extension ZIP processing missing `check_is_safe_zip`

**Reports:** import endpoint (`superset/importexport/api.py`) and
`get_bundle_files_from_zip` (`superset/extensions/utils.py`) extract ZIP entries "without"
`check_is_safe_zip` (ASVS 5.2.1 / 5.3.2, CWE-22/400).

**Verdict — FALSE POSITIVE.** Both paths **do** call `check_is_safe_zip` before reading entries:
`get_contents_from_bundle` (`superset/commands/importers/v1/utils.py:254`) calls it as its first line,
and `get_bundle_files_from_zip` (`superset/extensions/utils.py:159`) calls it before yielding. It
enforces per-file size and compression-ratio limits. *(A genuine residual gap — no aggregate-total cap
and a zero-division edge — was addressed separately in PR #40664.)*

## 12. `uuid3` (MD5-based) used for cache-key generation

**Report:** `superset/extensions/metastore_cache.py` uses `uuid3` (MD5) for cache keys (ASVS 11.4.1,
CWE-328).

**Verdict — FALSE POSITIVE.** This is deterministic key derivation (mapping a cache-key string to a
UUID for lookup), not a cryptographic use. MD5's collision/preimage weaknesses are irrelevant; there is
no confidentiality or authentication dependency. The report itself concedes it is "not for
security-critical cryptographic operations." Switching to `uuid5` would only invalidate existing cache
keys (a one-time cache miss) for no security benefit.

## 13. No startup validation that the encryption engine is AEAD

**Report:** `EncryptedFieldFactory` accepts any adapter without verifying an approved AEAD mode
(ASVS 11.3.2, CWE-327).

**Verdict — NON-ISSUE (as stated).** The default engine is `AesEngine` (AES-CBC), so a startup check
that *requires* AEAD would fail the default configuration. A hard AEAD assertion only becomes
meaningful **after** an AES-GCM migration — which is tracked as a separate, deliberate change (the
authenticated-encryption SIP / draft PR #40654). Adding the check now would either be a no-op or break
default installs.

## 14. Legacy database URI validator missing `check_sqlalchemy_uri()`

**Report:** `superset/views/database/validators.py` `sqlalchemy_uri_validator` omits
`check_sqlalchemy_uri()`, potentially bypassing `PREVENT_UNSAFE_DB_CONNECTIONS` (ASVS 2.2.1, CWE-20).

**Verdict — FALSE POSITIVE (dead code).** The claim that the function omits the check is literally true,
but the function is **unreachable** — the only symbol imported from that module anywhere is
`schema_allows_file_upload`; `sqlalchemy_uri_validator` has zero callers, and the legacy `DatabaseView`
exposes no URI-submission endpoint. All DB create/edit flows go through the REST API, whose validator
(`superset/databases/schemas.py:197-217`) correctly gates on `PREVENT_UNSAFE_DB_CONNECTIONS` and calls
`check_sqlalchemy_uri`. No bypass exists; optional dead-code removal only.

## 15. `row_limit` missing upper-bound validation

**Report:** `ChartDataQueryObjectSchema.row_limit` validates only `min=0`, enabling resource
exhaustion (ASVS 2.2.1, CWE-770).

**Verdict — FALSE POSITIVE.** Every requested `row_limit` is hard-capped server-side at execution time
by `apply_max_row_limit()` (`superset/utils/core.py`), which clamps to `SQL_MAX_ROW` (default 100000)
or `TABLE_VIZ_MAX_ROW_SERVER`. The resource-exhaustion premise is not met — execution never honors an
unbounded limit. A schema-level `max` would be cosmetic and risks contradicting deployments that raise
`SQL_MAX_ROW`.

## 16. Authentication rate limiting not active by default

**Report:** `AUTH_RATE_LIMITED` defaults to `False` (per Flask-AppBuilder), leaving login unprotected
(ASVS 6.3.1, CWE-307).

**Verdict — FALSE POSITIVE (for Superset).** Superset's `config.py:344-345` already overrides the FAB
default: `AUTH_RATE_LIMITED = True` and `AUTH_RATE_LIMIT = "5 per second"`. The limiter is gated to
production via `RATELIMIT_ENABLED = os.environ.get("SUPERSET_ENV") == "production"` by design (avoiding
rate-limiting noise in development). The premise — that a default Superset deployment has
`AUTH_RATE_LIMITED = False` — does not hold.

## 17. No protection against malicious account lockout

**Report:** Flask-AppBuilder's `AUTH_MAX_LOGIN_ATTEMPTS` locks accounts after N failed logins,
enabling an attacker to lock victims out (DoS); proposes auto-unlock and IP-rate-limit-before-lockout
(ASVS 6.3.1, CWE-645).

**Verdict — FALSE POSITIVE.** The premise is wrong for this Flask-AppBuilder version: there is **no
account-lockout mechanism at all.** `AUTH_MAX_LOGIN_ATTEMPTS` does not exist anywhere in FAB, and
`auth_user_db` only increments `fail_login_count` via `update_user_auth_stat` — it never checks a
maximum or locks the account. With no lockout, there is no lockout-DoS to defend against, and
"auto-unlock" would have nothing to unlock. (Brute-force is instead bounded by the rate limiting in
#16, which Superset enables by default.)
