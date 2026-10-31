# Application Security Review — AuthN/AuthZ Bypass & Privilege Escalation

**Tree:** `0513545dd` (`tiobagio/vault`, `version/VERSION` = `1.18.0-beta1`)  
**Scope:** Authentication/authorization bypass and privilege escalation with end-to-end attack paths.  
**Method:** Static tracing of identity/ACL/MFA/token/sys paths; PoC unit tests executed then removed from tree.

## Validated findings (MEDIUM+)

### 1. Identity entity/group ROOT policy case bypass (CVE-2025-5999) — HIGH

- **Attacker:** Privileged operator with write on root-namespace `identity/entity` or `identity/group` (not a root token).
- **Controlled input:** `policies` containing a case/spacing variant of `root` (e.g. `ROOT`, `Root`, `RoOt`, `" ROOT "`).
- **Reachability:** `POST/PUT /v1/identity/entity` (or by id/name) / `identity/group` in the **root** namespace. Victim/self must already hold a live entity-bound token (login first with normal policies).
- **Impact:** Existing entity-bound tokens inherit Vault `root` for the remainder of the token TTL (full admin). New logins while `root` is already assigned are blocked by `LoginCreateToken`.
- **Primary location:** `vault/identity_store_entities.go` (group twin: `vault/identity_store_groups.go`)
- **Remediation:** Reject root case-insensitively (and after trim), e.g. `StrListContainsCaseInsensitive`; normalize/lowercase policy names before persistence. Upgrade to CE ≥ 1.20.0 / Ent ≥ 1.18.11 (HCSEC-2025-13).

**PoC result:** Entity/group accept `ROOT`/`RoOt`; `SanitizePolicies` collapses to `["root"]`; ACL `IsRoot=true`. Lowercase `"root"` correctly rejected.

### 2. ACL identity-template slash (and trailing-`*`) path injection (CVE-2026-5006 + local wildcard gap) — MEDIUM

- **Attacker:** Authenticated principal who can control an identity value referenced by a templated ACL path (entity/alias/group metadata, custom_metadata, or name fields depending on policy).
- **Controlled input:** Identity value containing `/` (extra path segments) or trailing `*` (prefix grant) when rendered into `path "…"`.
- **Reachability:** Any request evaluated under a templated policy after the attacker updates the referenced identity value (e.g. `identity/entity` metadata write, or auth-synced metadata).
- **Impact:** Capabilities grant on unintended paths (slash) or entire path prefixes (trailing `*` → `IsPrefix=true`). CVSS 6.8 for slash injection (HCSEC-2026-32).
- **Primary location:** `sdk/helper/identitytpl/templating.go` (`aclTemplateHandler` returns strings verbatim); consumption in `vault/policy.go` `parsePaths`.
- **Remediation:** Upgrade to releases with `deny_slash_in_templated_paths` and enable it; reject `/`, `*`, and `+` in rendered ACL template values (later upstream hardening). Prefer templating on immutable IDs.

**PoC result:** `department=admin/super-secret` renders `secret/data/admin/super-secret` and allows read. `team=*` renders prefix `secret/data/` and allows all under that prefix. Mid-path `*` is literal (not a segment wildcard) on this tree.

### 3. Cert auth non-CA leaf CN impersonation (CVE-2025-6037) — MEDIUM

- **Attacker:** Holder of a trusted non-CA client certificate and its private key.
- **Controlled input:** Crafted client cert with same serial + AKI + public key as the trusted leaf, but arbitrary Subject CN.
- **Reachability:** TLS client auth → `POST /v1/auth/cert/login` → non-CA match in `verifyCredentials`.
- **Impact:** Alias name becomes the forged CN → attach to victim entity (policies/groups). Token also receives the matched cert role’s policies.
- **Primary location:** `builtin/credential/cert/path_login.go`
- **Remediation:** Require presented leaf to equal the registered trusted leaf (or pin CN/SANs to the registered cert). Avoid non-CA trusted certs; use CA-issued clients. Upgrade to CE ≥ 1.20.1 / Ent ≥ 1.18.12 (HCSEC-2025-18).

**PoC result:** Forged CN `bob` with Alice’s serial/AKI/key authenticates; `Auth.Alias.Name == "bob"` with Alice role policies.

## Rejected candidates (not MEDIUM+ exploitable authz bypass here)

| Candidate | Why rejected |
| --- | --- |
| Login MFA enforcement gaps (`sys/mfa/validate` unauthenticated) | By design for two-phase login; still requires valid `mfa_request_id` + successful MFA method validation before token mint. Entity-nil + mount MFA correctly denies. |
| ACL policy `mfa_methods` not enforced on CE | Enterprise-only path via `performEntPolicyChecks` stub; product limitation, not a CE regression vs documented Login MFA. |
| Token create orphan / sudo / root minting | `create-orphan` and `no_parent` require sudo; root child tokens require root parent; policies sanitized before root check; subset enforcement for non-sudo. |
| Unauthenticated `sys/generate-root`, `sys/rekey*`, seal/unseal | Shamir/recovery key gated by design; not an authz bypass. |
| Metrics/pprof unauthenticated access | Explicit listener config flags only. |
| Entity merge copying policies | Only merges already-stored policies; no new assignment bypass beyond finding #1. |
| Mid-path `*` in templates as wildcard | Literal path segment on this ACL engine; not a wildcard grant. |
| SSH CA empty `valid_principals` (CVE-2024-7594) | Real issue class but outside this pass’s authN/authZ Vault-token focus (secrets-engine SSH cert issuance). |

## Notes

- Finding #1 does **not** require assigning lowercase `root`; case variants are sufficient because write-time checks are case-sensitive while request-time `SanitizePolicies` lowercases.
- Finding #1 is root-namespace only: `NewACL` rejects policy name `root` outside root NS.
- Finding #2’s trailing-`*` behavior is an additional local amplification on this pre-hardening tree; upstream advisory for CVE-2026-5006 centers on `/`.
