# Application Security Review — HashiCorp Vault 1.18.0-beta1

**Target:** `/workspace` @ `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`1.18.0-beta1`)  
**Branch:** `cursor/application-security-review-651e`  
**Scope note:** Skipped already-reported CVE/HCSEC list from the review brief (CVE-2025-6000/5999/7594/11621/6037/6013–6015/6004/6011/5052/4525/8185/6203/5807/4166/3605/3879 and related). Also skipped Redshift/HANA SQLi per brief.

---

## Finding 1 — PostgreSQL database secrets engine: unquoted schema in default revoke (SQL injection)

| Field | Value |
| --- | --- |
| **Severity** | Medium (aligned with OpenBao CVE-2026-39946 / GHSA-6vgr-cp5c-ffx3, CVSS 3.1 4.9) |
| **CWE** | CWE-89 (SQL Injection) |
| **Primary location** | `plugins/database/postgresql/postgresql.go` — `PostgreSQL.defaultDeleteUser` |
| **Status in this tree** | **Vulnerable** (unquoted `schema` on REVOKE ALL TABLES). Fixed upstream later in HashiCorp PR [#28519](https://github.com/hashicorp/vault/pull/28519) (merged 2024-09-26; this beta is 2024-06-06). |
| **Also tracked as** | OpenBao CVE-2026-39946 (inherited from Vault; **not** in the skip list) |

### Vulnerable code

In `defaultDeleteUser`, schemas are loaded from `information_schema.role_column_grants` and interpolated into SQL. The username is quoted; the schema on the first REVOKE is not. The immediately following REVOKE USAGE correctly quotes the same schema — inconsistent and unsafe:

```445:453:plugins/database/postgresql/postgresql.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(
			`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %s FROM %s;`,
			(schema),
			dbutil.QuoteIdentifier(username)))

		revocationStmts = append(revocationStmts, fmt.Sprintf(
			`REVOKE USAGE ON SCHEMA %s FROM %s;`,
			dbutil.QuoteIdentifier(schema),
			dbutil.QuoteIdentifier(username)))
```

Those statements are executed via the Vault **management** DB connection:

```486:489:plugins/database/postgresql/postgresql.go
	for _, query := range revocationStmts {
		if err := dbtxn.ExecuteDBQueryDirect(ctx, db, nil, query); err != nil {
			lastStmtError = err
		}
```

`ExecuteDBQueryDirect` runs `db.ExecContext` on the fully interpolated string (`sdk/helper/dbtxn/dbtxn.go`). Proper quoting is available in-tree (`sdk/database/helper/dbutil/quoteidentifier.go`) but not applied to this schema use.

Default revoke is used when no custom `revocation_statements` are configured (`DeleteUser` → `defaultDeleteUser`).

### Attacker / controlled input

- **Attacker:** A principal with high privileges on the **target PostgreSQL database** (ability to create schemas with arbitrary names and grant column privileges to Vault-managed roles). Not a Vault root token; typically a DB admin, compromised app role with `CREATE`, or co-tenant with schema DDL rights.
- **Controlled input:** PostgreSQL schema name (and grants onto a Vault-issued dynamic role). Schema names may contain SQL metacharacters when created as quoted identifiers, e.g. `CREATE SCHEMA "public; <payload>; --";`. Names are constrained by PostgreSQL `NAMEDATALEN` (63 bytes).

### End-to-end attack path

1. Vault PostgreSQL database secrets engine is configured with a privileged management user; a dynamic role uses **default** revocation (empty / unset `revocation_statements`).
2. Attacker creates a malicious schema name containing SQL metacharacters and objects; grants column privileges on those objects to a Vault-managed dynamic role (or waits for Vault to issue a lease and then grants).
3. `information_schema.role_column_grants` returns that schema for the grantee.
4. Lease expiry or explicit credential revoke causes Vault to call `defaultDeleteUser`.
5. Vault builds  
   `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA <raw-schema> FROM "<quoted-user>";`  
   without quoting `<raw-schema>`, so metacharacters alter statement structure.
6. Statement runs as the **Vault management DB user**.

### Impact

- **Reliable:** Revocation failures / incomplete cleanup (orphan DB roles, residual grants) — integrity of the secrets lifecycle.
- **Less common but higher impact:** SQL injection as the management user (statement rewriting / additional commands depending on driver simple-query behavior), enabling unauthorized DDL/DCL/DML under that account’s privileges. OpenBao rated confidentiality High under CVSS 3.1 for the successful injection case.

### Fix direction (for maintainers)

Apply `dbutil.QuoteIdentifier(schema)` to the REVOKE ALL TABLES statement (as already done for REVOKE USAGE and as in PR #28519). Workaround: audit schemas; deny untrusted DB users ability to create schemas / grant on them; use custom revocation statements that do not consult untrusted schema names unsafely.

### Why this is in scope

- Not Redshift/HANA (Redshift in this tree already quotes schema in the analogous path).
- Not in the provided already-reported CVE skip list.
- Present and exploitable in this exact commit with a concrete code path.

---

## Areas reviewed without new medium+ findings (summary)

| Area | Result |
| --- | --- |
| MSSQL physical storage SQLi (CVE-2023-0620 class) | Mitigated via `identifierRegex` / `isInvalidIdentifier` in `physical/mssql/mssql.go` |
| AppRole secret-id destroy cross-role | Mitigated; regression coverage present |
| SSH empty principals | Present but **skipped** (CVE-2024-7594) |
| PKI ACME SSRF | Present but **skipped** (CVE-2026-5052) |
| Identity root policy case | Present but **skipped** (CVE-2025-5999) |
| Credential backends (AppRole/GitHub/Okta/RADIUS/LDAP/AWS beyond skip list) | No additional defended medium+ E2E path locked in this pass |
| Agent/proxy sinks, audit file backend, CORS/raw (beyond known config surfaces) | No novel medium+ authz/RCE finding defended |
| Cassandra/Influx `QueryHelper` username substitution | Unsafe string replace exists; chaining via auth DisplayName needs fragile conditions — not reported as standalone medium+ without a tighter E2E |

---

## Evidence checklist (Finding 1)

- [x] Attacker model defined (DB-privileged / schema creator)
- [x] Controlled input identified (schema name via grants → catalog → revoke SQL)
- [x] Reachability: default DeleteUser → `defaultDeleteUser` → `ExecuteDBQueryDirect`
- [x] Impact: revoke integrity failure + SQLi as management user
- [x] Primary path: `plugins/database/postgresql/postgresql.go`
