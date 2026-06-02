# Review comments — sha174n's open security PRs

Paste-ready, terse review comments. **Blockers only** (correctness / security /
breaking behavior) — CI, rebasing, and nitpicks omitted per request.
Legend: ✅ no blockers · ⚠️ confirm intent before merge · ⛔ blocker.

Summary: **1 blocker (#39301), 3 confirm-intent (#40499, #40421, #40329, #38452), rest clean.**

---

### #39301 — fix(network): validate target hostname in outbound requests  ⛔
> The webhook and dataset-import SSRF guards look right, but the **Databend** change is a blocker: `db_engine_specs/databend.py` swaps `is_hostname_valid` for `is_safe_host`, which rejects all private/RFC-1918/loopback IPs as a hard error. A Databend server on an internal network is a normal deployment, and a DB-connection host isn't an SSRF sink the way an outbound fetch is — this blocks saving/testing valid internal connections with no opt-out (the dataset-import path got `DATASET_IMPORT_ALLOW_INTERNAL_DATA_URLS`; this didn't). It's also inconsistent with clickhouse/databricks/couchbase, which still use `is_hostname_valid`. Please revert the databend spec to `is_hostname_valid` (or gate it behind a flag); the webhook/import guards are good to go.

---

### #40499 — fix(sql): cap parser input length via SQL_MAX_PARSE_LENGTH  ⚠️
> Wiring is correct (all sqlglot entry points, UTF-8 byte count, `None` disables, app-context fallback) and the `transpile_to_dialect` error contract is preserved. One thing to confirm: the **1 MB default** now rejects any single query exceeding it — e.g. a very large `IN (...)` list or a big virtual-dataset SQL — in SQL Lab and dashboard-generated queries. It's configurable, but please sanity-check 1 MB against real query sizes in target deployments before merge.

### #40421 — fix(sql): broaden mutating-statement detection  ⚠️
> No false positives on legitimate SELECT/CTE/subquery/`SET search_path` (verified — those stay non-mutating), and function-name matching is exact (a column/alias named `setval` isn't flagged). Confirm the **intended UX change**: `SHOW` / `SET ROLE` / `CALL` / `EXECUTE` are now classified as mutating, so on read-only DBs (`allow_dml=False`) users who previously ran `SHOW search_path` / `SHOW server_version` will now get DML-not-allowed. Fine if intended — just a user-facing behavior change to flag in the description.

### #40329 — fix(tag): validate object access in tag create/delete  ⚠️
> Single-object path correctly uses `raise_for_access` (so tagging objects you can *view* but don't own still works for chart/dashboard/dataset) — good. Two things to confirm: (1) it changes `to_object_model` from the access-scoped DAO `find_by_id` to unfiltered `db.session.get`, which flips the bulk-tag perm test (`objects_tagged 2→1`) — intended? (2) the SavedQuery branch enforces **creator-only**, so a non-admin who can see a shared saved query but didn't create it can't tag it — acceptable given SavedQuery is creator-scoped, but worth a sentence. (Also overlaps with #40333 on the same files — heads-up on ordering.)

### #38452 — fix(rls): extend RLS validation coverage  ⚠️
> The predicate-validation core is solid — I checked `name='x'`, `1=1`, `IN`, casts, function calls, `OR`, `SIMILAR TO`, Jinja clauses: all pass unchanged, and set-ops/multi-statement/subquery-without-flag are correctly blocked. Two intended-but-impactful behavior changes to confirm don't regress prod: (1) `get_from_clause` now **fails closed** (raises) when RLS can't be applied to a virtual dataset's SQL instead of best-effort log-and-continue — a virtual dataset with dialect-specific SQL sqlglot can't round-trip will now hard-fail; (2) DML on RLS-protected tables is now blocked under `RLS_IN_SQLLAB`. Both are the right security direction — just verify no legitimate virtual datasets regress.

---

### #40568 — fix(charts): DISALLOWED_SQL_FUNCTIONS gate on adhoc expressions  ✅
> No blockers. Mirrors the canonical `_validate_query` logic; the `SELECT` double-wrap heuristic is safe (bare `select_count` identifiers and real subqueries handled correctly), catches `MAX(version())` wrapper-bypass, and skips when denylists are empty.

### #40567 — fix(charts): enforce DISALLOWED_SQL_* at chart-data execution  ✅
> No blockers. Inserted on the final rendered SQL in `SqlaTable.query()` before `get_df`, using the same engine-keyed config as the sql_lab gate. Closes the chart-data bypass; no false-positive risk for normal dataset tables.

### #40566 — fix(redirect): normalize browser-stripped whitespace  ✅
> No blockers. The regex matches exactly the WHATWG-stripped chars (TAB/LF/CR, literal + percent-encoded) and strips before the leading-`//` and `urlparse` checks, closing the `/%09///host` bypass without making relative URLs look external.

### #40531 — fix(jinja): dialect-escaped companion on get_filters()  ✅
> No blockers. `_escape_value` reuses the established-safe `url_param` pattern (`literal_processor(dialect)`), is additive/backward-compatible, escapes lists element-wise, and retains raw `val` for `where_in`/comparisons. Correct split for LIKE/string interpolation.

### #40497 — fix(views): per-chart access check in legacy form_data endpoint  ✅
> No blockers. `ChartDAO.get_by_id_or_uuid` applies the same `ChartFilter` as `ChartRestApi.get` and raises `ChartNotFoundError` (→404) for both missing and forbidden, so no enumeration leak. Genuinely covers the path.

### #40396 — fix(dashboards): narrow datasets payload to read-access callers  ✅
> No blockers. Stripped fields (`sql`, `select_star`, `fetch_values_predicate`, `template_params`, `params`, column/metric `expression`) are SQL-definition metadata not used for rendering; the FE consumer and chart-data API rely on names/verbose maps, which are retained. `dump` returns fresh dicts so the `pop`s don't corrupt shared state. Pure narrowing — dashboards still work.

### #40392 — fix(dataset): unify validation for stored and adhoc SQL  ✅
> No blockers. Moves the same `validate_adhoc_subquery` + `sanitize_clause` gate that already runs at query time to save time, so nothing legitimate that runs today would newly fail. Verified CASE/SUM/window/cast/arithmetic parse cleanly; Jinja and CTE/subquery handling is correct.

### #40336 — fix(chart): standardize dashboard validation across create/update  ✅
> No blockers. Update now mirrors create exactly — ownership checked only on **new** dashboard relationships (existing ones preserved), `DashboardsForbiddenError`→403 with `status`/`message` present. Not breaking for legitimate edits.

### #40333 — fix: dashboard access check in related_objects endpoints  ✅
> No blockers. Filters related charts/dashboards through `can_access_chart`/`can_access_dashboard` (view access, not ownership), consistent across databases & datasets APIs — hides invisible related objects without breaking legitimate listing. (Touches the same files as #40329 — heads-up on ordering.)

### #40327 — feat(docker): environment-based debugger control  ✅
> No blockers. Safe defaults: without `SUPERSET_DEBUG_ENABLED=true` the `app` target forces `FLASK_DEBUG=0` + `--no-debugger` (overriding any inherited `.env`), and the production `app-gunicorn` path is untouched.

### #40245 — fix(sqllab): quote CTAS identifiers + validate tmp_table_name  ✅
> No blockers. `exp.Identifier(quoted=True)` correctly prevents identifier injection; the regex permits empty/bare identifiers only and uses `\Z` (no trailing-newline bypass). Schema is supplied separately, so valid usage isn't broken. Applied to both payload schemas.

### #39302 — fix(embedding): optional dataset allowlist on guest tokens  ✅
> No blockers. Fully opt-in: claim only written when non-None, enforcement only fires when `allowed_datasets is not None`, tokens without the claim keep default access, malformed claims fail closed.

### #39303 — fix(api): per-object ownership validation in commands  ✅
> No blockers re: legitimate non-owner flows. The chart/dashboard checks use `raise_for_access` (viewability, not ownership) and run only on report create/update — **not** the report-worker/execution path, so scheduled runs are unaffected. A user creating a report on a chart they can view but don't own still passes; `ReportScheduleForbiddenError`→403.

### #39304 — fix(chart): restrict owner lookup to write-access users  ✅
> No blockers. Gated on `can_access_all_datasources()`, which is true for Admin **and Alpha** (the standard editor role), so the owners dropdown still works for legitimate editors; only read-only/Gamma get 403, matching intent.
