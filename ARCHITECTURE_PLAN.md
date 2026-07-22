# Enterprise IdP — Architecture & Implementation Plan
**For:** Top Indian bank — Retail, Employee, Corporate/B2B, Fintech-Partner, Vendor/Merchant/NTB IAM
**Source requirements:** `Enterprise_IdP_Blueprint.md`
**Live infra (not precedent — actually running):** Ory Hydra (OAuth2/OIDC, on CockroachDB), Permify (ReBAC authorization), Ory Kratos (legacy internal identity store, being migrated off)
**Research basis:** 110-agent deep-research pass, 27 primary/secondary sources fetched, 25 claims adversarially verified (23 confirmed 3-0 or 2-1, 2 explicitly refuted and excluded — see §11). Full citations in §12.

---

## 0. How this document differs from the previous plan

The version of this file previously committed (`git show HEAD:ARCHITECTURE_PLAN.md`, commit `4ccad2a`) locked in a decision that **this IdP does not mint OAuth2 tokens; a separate in-house Authorization Server does, modeled on Hydra's login-delegation pattern.** That assumption is now void: **Hydra itself is the live AS.** Every place the old plan said "the bank's in-house AS," read "Ory Hydra." The Auth-Delegate Adapter concept collapses into "the Identity Service *is* Hydra's login/consent provider" — one fewer integration hop, one fewer thing to keep in sync.

Second correction: the old plan chose Postgres with RLS / schema-per-tenant for isolation, modeled on WSO2/Keycloak. This plan aligns isolation with **Permify's own verified pattern** (shared instance, row-level `tenant_id`) to avoid a mismatched isolation model between the IdP and the authorization engine it depends on, and targets **CockroachDB** (not Postgres) so the IdP's data layer, Hydra's data layer, and Permify's data layer can share one HA cluster.

---

## 1. System context & actors

```
                         ┌───────────────────────────────────────────┐
                         │              Tenants (isolated by         │
                         │              tenant_id, row-level)         │
                         │                                             │
  Retail customers ──────┼──▶ tenant_type=retail                      │
  Employees/staff ───────┼──▶ tenant_type=employee (ex-Kratos)        │
  Corporate/B2B ─────────┼──▶ tenant_type=corporate (+ sub-org via     │
                         │      Permify relation hierarchy)            │
  Fintech partners ──────┼──▶ tenant_type=partner (OAuth client-heavy) │
  Vendors/Merchants/NTB ─┼──▶ tenant_type=vendor                      │
                         └───────────────────────────────────────────┘
```

Each tenant type differs mainly in **policy** (session length, MFA strictness, which external provider it's wired to, OAuth client population) — not in a structurally different code path. This is what row-level tenancy buys: one flow engine, N policy sets.

---

## 2. Reference architecture

```
                                   ┌─────────────────────┐
     Internet / Partner APIs ─────▶│   API Gateway / BFF  │  WAF, rate limiting,
                                   │  (per-channel: retail│  per-tenant routing
                                   │  app, corp portal,   │
                                   │  employee SSO, AA/   │
                                   │  partner API)        │
                                   └──────────┬───────────┘
                                              │
              ┌───────────────────────────────┼────────────────────────────────┐
              ▼                               ▼                                ▼
     ┌─────────────────┐           ┌────────────────────┐            ┌──────────────────┐
     │  Identity        │◀─────────▶│   Ory Hydra         │            │  Permify           │
     │  Service         │  login/   │  (OAuth2/OIDC AS,   │            │  (ReBAC engine,    │
     │  (this build)    │  consent  │  headless, no user  │            │  tenant_id-scoped  │
     │                  │  contract │  store, cockroach:// │            │  relation tuples)  │
     └────────┬─────────┘           │  DSN)                │            └─────────┬──────────┘
              │                     └──────────┬───────────┘                      │
              │                                │                                  │
              ▼                                ▼                                  ▼
     ┌──────────────────────────────────────────────────────────────────────────────────┐
     │                     CockroachDB — shared multi-region HA cluster                  │
     │   database `idp`      database `hydra`        database `permify`                  │
     │   (identities,        (oauth2_client,          (relation_tuple,                    │
     │   credentials refs,   consent_request,         schema_definition,                  │
     │   sessions, tenant    flow tables — Hydra's     tenant metadata —                   │
     │   config, audit,      own migrations)           Permify's own migrations)           │
     │   dpdp_consent,                                                                     │
     │   migration_state)                                                                  │
     │   super-regions constrained to India-designated regions · REGION survival goal      │
     └──────────────────────────────────────────────────────────────────────────────────┘
              │
              ▼
     ┌──────────────────────────────────────────────────────────────────────────────────┐
     │              External Auth-Factor & Notification Adapters (this build)             │
     │  OTPProviderAdapter · TOTPProviderAdapter · PasskeyProviderAdapter ·                 │
     │  NotificationProviderAdapter — each resolves, per tenant_id, to the bank's actual    │
     │  enterprise OTP / TOTP / Passkey / Notification service. No secrets/OTP codes        │
     │  persist inside the IdP beyond a short-lived correlation reference.                  │
     └──────────────────────────────────────────────────────────────────────────────────┘

     ┌──────────────────┐        ┌──────────────────────┐       ┌────────────────────┐
     │  Ory Kratos        │◀─────▶│  Migration Bridge      │      │  Audit / Compliance │
     │  (legacy, employee │ OIDC  │  (federation during   │      │  Service (WORM,     │
     │  identities —      │ fed.  │  cutover; credential  │      │  hash-chained)      │
     │  being retired)    │       │  import; dual-write)  │      └────────────────────┘
     └──────────────────┘        └──────────────────────┘
```

### Component responsibilities

| Component | Owns | Does NOT own |
|---|---|---|
| **Identity Service** (new build) | Identity lifecycle, flow state machines (login/registration/recovery/verification/settings), session issuance, tenant config, hook/webhook extension points, Hydra login/consent contract implementation | OAuth token minting (Hydra), authorization decisions (Permify), OTP/TOTP secret generation or Passkey ceremony crypto (external services), notification delivery (external service) |
| **Ory Hydra** | OAuth2/OIDC token issuance, JWKS, introspection/revocation, consent-grant storage | User authentication UX, identity storage |
| **Permify** | Relationship-based authorization decisions, tenant-scoped relation tuples, entitlement hierarchies for corporate/B2B | Identity data, session state |
| **External OTP/TOTP/Passkey/Notification services** | Generating/verifying OTP and TOTP, WebAuthn/Passkey ceremony, delivering Email/SMS | Anything about who the user is or what they're allowed to do |
| **Ory Kratos** (during migration only) | Source-of-truth identity for not-yet-migrated employee tenants | Nothing new — frozen scope, shrinking over time |

---

## 3. Data model (CockroachDB, database `idp`)

```
tenants
  tenant_id            UUID PK
  tenant_type          ENUM(retail, employee, corporate, partner, vendor)
  name                 TEXT
  data_residency_region TEXT        -- must resolve to an India super-region
  status               ENUM(active, suspended, migrating, decommissioning)
  created_at           TIMESTAMPTZ

tenant_config
  tenant_id            UUID FK -> tenants
  capability           ENUM(otp, totp, passkey, notification)
  provider_ref         TEXT         -- logical name of the external enterprise service
  endpoint_config      JSONB        -- non-secret routing/config
  secret_ref           TEXT         -- pointer into KMS/secrets manager, never the secret itself
  PRIMARY KEY (tenant_id, capability)

identities
  identity_id          UUID PK
  tenant_id            UUID FK -> tenants   -- row-level isolation key, mandatory on every query
  traits               JSONB        -- schema mirrors Kratos identity traits for migration compatibility
  state                ENUM(active, inactive, migrating)
  source_system        ENUM(native, kratos_migrated)
  created_at           TIMESTAMPTZ
  INDEX (tenant_id, identity_id)

credentials
  credential_id        UUID PK
  identity_id          UUID FK -> identities
  tenant_id            UUID          -- denormalized for isolation-check speed
  type                 ENUM(password, otp_ref, totp_ref, passkey_ref)
  -- password: hash + algo tag only
  -- otp_ref / totp_ref / passkey_ref: correlation reference to the external
  --   enterprise service; no OTP code, TOTP seed, or private key material lives here
  external_credential_ref TEXT
  created_at           TIMESTAMPTZ
  updated_at           TIMESTAMPTZ

sessions
  session_id           UUID PK
  identity_id          UUID FK -> identities
  tenant_id            UUID
  aal                  ENUM(aal1, aal2, aal3)   -- authenticator assurance level
  devices              JSONB
  expires_at           TIMESTAMPTZ
  revoked_at           TIMESTAMPTZ NULL

dpdp_consent_ledger
  consent_id           UUID PK
  identity_id          UUID FK -> identities
  tenant_id            UUID
  purpose              TEXT          -- DPDP-scoped purpose, distinct from Hydra's OAuth consent grants
  granted_at           TIMESTAMPTZ
  withdrawn_at         TIMESTAMPTZ NULL

audit_log
  audit_id             UUID PK
  tenant_id            UUID
  actor_identity_id     UUID
  action               TEXT
  before_state          JSONB
  after_state           JSONB
  hash_prev            BYTES         -- hash-chained for tamper-evidence (WORM store downstream)
  occurred_at          TIMESTAMPTZ

migration_state
  identity_id          UUID FK -> identities
  kratos_identity_id    UUID
  migration_status      ENUM(not_started, credentials_imported, dual_write, cutover_complete)
  cutover_batch         TEXT
  updated_at           TIMESTAMPTZ
```

**Deliberate omissions:** no `oauth_client` table (that's Hydra's `hydra` database), no `relation_tuple` table (that's Permify's `permify` database), no OTP-code or TOTP-seed columns anywhere (those live only in the external enterprise services — this schema stores references, never secrets).

**Permify schema sketch** (owned by Permify, shown here only to make the entitlement mapping explicit for corporate/B2B):
```
entity tenant {}
entity organization {
  relation parent @tenant
  relation admin @identity
  relation member @identity
  action manage = admin
  action view = admin or member
}
entity account {
  relation owner @organization
  action view = owner.member
  action transact = owner.admin
}
```
This is the concrete mechanism for "corporate/B2B delegated administration with complex entitlement hierarchies" — a sub-org's `member` inherits `view` on its accounts via the `owner.member` cascade, without the IdP itself modeling org charts.

---

## 4. Multi-tenancy isolation strategy

| Layer | Mechanism | Rationale |
|---|---|---|
| Permify | Shared instance, mandatory `tenant_id` on every `Check()` call, row-level `tenant_id` on relation-tuple and schema tables | This is Permify's own documented and recommended model — not a choice this project gets to make differently without fighting the tool |
| IdP data layer | Row-level `tenant_id` on every table, enforced at the query layer (every repository method requires a `tenant_id` argument — no "get by ID" without it) | Matches Permify's model 1:1, so there is no isolation-model seam between authentication and authorization |
| Hydra | OAuth clients tagged with `tenant_id` in client metadata; login/consent contract carries `tenant_id` through the `login_challenge` context | Hydra itself is tenant-agnostic (it has no concept of tenants) — tenancy is layered on top via the Identity Service, which is the only thing that talks to Hydra's admin API |
| CockroachDB | One shared cluster, separate `idp` / `hydra` / `permify` databases (not separate clusters) | Avoids running three independent HA clusters; blast-radius separation is at the database/schema level, physical HA is shared |
| Highest-sensitivity tenants (large corporate) | **Do not** introduce a different isolation primitive (e.g. schema-per-tenant) just for these — it would diverge from Permify's model and add an inconsistency the authorization layer can't see. Instead, use tighter Permify schema-level restrictions plus additional audit-log granularity for these tenant_ids. | An open question in the research (see §11 "open questions") is whether Permify has published tenant-count/blast-radius guidance at bank scale — treat cluster-per-tenant as a fallback to revisit only if that guidance, once obtained, says row-level is insufficient for this tenant class |

### 4.1 Cross-tenant access violation defenses (the part row-level `tenant_id` alone does not solve)

Row-level `tenant_id` only isolates tenants if `tenant_id` is *trustworthy*. If any service accepts `tenant_id` as a client-supplied parameter (header, body field, query string) and filters on it directly, then knowing or guessing another tenant's ID is sufficient to read that tenant's data — this is OWASP API1:2023 Broken Object Level Authorization, at tenant granularity, and it is **not** prevented by RLS or row-level columns on their own. The defense is layered, so no single bug or omission is sufficient to leak across tenants:

| Layer | Mechanism | What it stops |
|---|---|---|
| **1. Trust boundary at token issuance** | `tenant_id` is resolved server-side from the authenticated identity's own record and embedded as a signed claim in the Hydra-issued access/ID token. No service reads `tenant_id` from a request header, body, or query parameter — ever. The API Gateway strips/ignores any client-supplied tenant field before forwarding and injects the token-derived value. | An attacker who knows tenant B's ID cannot act as tenant B without a token whose signature proves it — i.e. without actually compromising tenant B's credentials or Hydra's signing key. This is the primary fix for "tenant_id is known." |
| **2. Database-level backstop — CockroachDB Row-Level Security** | RLS (`ENABLE ROW LEVEL SECURITY` + `CREATE POLICY ... USING (tenant_id = current_setting('app.current_tenant')::uuid)`) on every multi-tenant table. The `app.current_tenant` session variable is set once per request from the *verified token claim*, never from a parameter. | Application-layer bugs — a missing `WHERE`, a raw/ad hoc query, an ORM footgun, a future contributor's mistake — can no longer return foreign-tenant rows, because the database enforces the filter independently of the query that was actually written. |
| **3. Permify `Check()` as a second, independent authority** | Permify's `tenant_id` argument is likewise server-derived, never client-supplied. More importantly, `Check()` validates the *relation* between subject and resource, not just a tenant match — there is no relation tuple connecting an identity to another tenant's resources, so even a hypothetical wrong tenant_id still gets denied. | A bug that defeats layer 1 or 2 alone still has to defeat the relation graph — the three layers do not share a single point of failure. |
| **4. Network segmentation** | CockroachDB and Permify's Check/Admin APIs are reachable only from backend services on a private network/mTLS mesh — never directly by client apps or partner integrations. | Knowing a tenant_id (or even a connection string fragment) is useless if the caller can't reach the systems that would act on it. |
| **5. Adversarial testing as a CI gate** | Automated BOLA/IDOR-style tests on every PR touching a repository method or authorization path: forged/mismatched tenant claims, valid token + enumerated foreign resource IDs, requests that attempt to bypass the gateway and hit Permify/CockroachDB directly. | Converts "we believe isolation holds" into "isolation is checked on every change," which is what the fitness function in §8 actually requires — a manual review is not a substitute for this. |
| **6. (Optional, for highest-sensitivity corporate/B2B tenants) Per-tenant envelope encryption** | Sensitive columns encrypted with tenant-scoped Data Encryption Keys via KMS, on top of CockroachDB's cluster-wide Encryption at Rest. | Even a catastrophic failure of layers 1–4 simultaneously (e.g. an RLS policy misconfigured during a migration) returns ciphertext unreadable without the correct tenant's key — a backstop of last resort, not a substitute for the layers above. |

**Audit signal, not just enforcement:** log every request where a client-asserted tenant field (if one is present at all, e.g. in a legacy integration payload) disagrees with the verified token's `tenant_id` claim — even though the client-asserted value is always ignored for authorization decisions, a mismatch is a probing signal worth alerting on.

---

## 5. CockroachDB HA / data-layer topology

- **Regions:** 3+ India-designated regions (exact cloud regions depend on the chosen provider's India footprint), enabling the `REGION` survival goal — the cluster automatically raises replication factor (2+2+1 pattern) to survive a full region loss, at a documented write-latency cost.
- **Super-regions:** used to constrain all voting and non-voting replicas of India-resident data to the India-designated region set — this is the concrete, vendor-documented mechanism for satisfying RBI data-localization/domiciling obligations for the live cluster.
- **Encryption at rest:** enabled cluster-wide (AES, two-tier store-key/data-key architecture).
- **Backups — explicit gate, not optional:** CockroachDB's cluster-wide Encryption at Rest does **not** automatically encrypt `BACKUP` statement output. Every backup job for this cluster must explicitly specify an encryption key or KMS at backup time, or the RBI-regulated data in that backup is unencrypted at rest in the backup target. This must be a CI/ops gate (fail the backup job if no KMS param is present), not a documentation note.
- **Shared cluster, separate databases:** `idp`, `hydra`, `permify` databases in one cluster — Hydra already has first-class CockroachDB support (dedicated `cockroach://` DSN and migrations), so this is a genuine code-level integration, not a compatibility hack.
- **Row-Level Security:** CockroachDB ships stable `ENABLE ROW LEVEL SECURITY` / `CREATE POLICY` support (Postgres-compatible syntax) — used as the database-level backstop for tenant isolation described in §4.1, not as the sole isolation mechanism.
- **Connection budgeting:** three consumers (Identity Service, Hydra, Permify) on one cluster means connection-pool sizing and query-load isolation (e.g. per-database resource limits, if the provider's CockroachDB offering supports them) must be planned before go-live, not discovered under load.

---

## 6. Pluggable external auth-factor & notification integration

The extension mechanism is a **flow hook system**, modeled deliberately on Ory Kratos's own before/after hooks on its five self-service flows (login, registration, recovery, settings, verification) — proven pattern, and it's also the exact mechanism the Kratos migration bridge needs (see §9).

```
LoginFlow.beforeSubmit  → hook: resolve tenant_config[tenant_id][capability] → provider adapter
LoginFlow.afterVerify   → hook: notify (async, non-blocking) via NotificationProviderAdapter
RegistrationFlow.*      → hook: passkey enrollment via PasskeyProviderAdapter
RecoveryFlow.*          → hook: OTP dispatch via OTPProviderAdapter, notification via NotificationProviderAdapter
```

**Adapter interfaces (conceptual, not literal code):**
- `OTPProviderAdapter`: `generateAndSend(tenant_id, identity_id, channel)`, `verify(tenant_id, correlation_ref, code)`
- `TOTPProviderAdapter`: `enroll(tenant_id, identity_id)`, `verify(tenant_id, correlation_ref, code)`
- `PasskeyProviderAdapter`: `beginRegistration(tenant_id, identity_id)`, `finishRegistration(...)`, `beginAssertion(...)`, `finishAssertion(...)` — the IdP relays WebAuthn ceremony data to/from the browser but the external service performs the cryptographic verification
- `NotificationProviderAdapter`: `send(tenant_id, identity_id, template, channel)` — Email/SMS delivery is entirely the external service's responsibility

**Per-tenant resolution:** every adapter call starts by reading `tenant_config[tenant_id][capability]` to determine which concrete enterprise-service endpoint to call. A retail tenant and a corporate tenant can point at different OTP providers (or different configs of the same provider) without any code branching — only config changes.

**Why this satisfies "integrate, don't rebuild":** the IdP never has an OTP-generation algorithm, a TOTP seed-derivation function, or WebAuthn attestation-verification logic of its own. If none of those adapters can reach their configured external service, the corresponding auth method fails closed — the IdP has no fallback native implementation to fall back to, by design.

---

## 7. Ory Kratos → new IdP migration strategy

| Phase | What happens | Risk gate before proceeding |
|---|---|---|
| **1. Schema mapping** | Map Kratos identity `traits` schema to the new `identities.traits` JSONB shape; inventory every internal system currently calling Kratos's public/admin API | None of Kratos's current internal integrations may be touched yet |
| **2. Federation bridge** | Kratos registered as an upstream OIDC IdP federated *into* the new Identity Service (which fronts Hydra). Employees still authenticate against Kratos; Hydra still issues the eventual token. No employee-facing behavior change. | Federation bridge passes parity tests against a sample of existing employee logins |
| **3. Credential import** | Bulk-import Kratos's pre-hashed credentials (Kratos supports 10 hash algorithms — BCrypt, Argon2, MD5, SHA variants, SSHA variants, PBKDF2, SCrypt, Firebase SCrypt, crypt(3), HMAC — via its Admin API or a migration hook) into the new IdP's `credentials` table. **No forced password reset at import time** — imported credentials bypass policy validation and are honored as-is; users are nudged to a policy-compliant credential later via self-service, not blocked. | Import job is idempotent and re-runnable; a sample of imported credentials verifies successfully against the new IdP's login flow before any batch is called complete |
| **4. Dual-write / shadow mode** | New registrations and profile updates written to both Kratos and the new IdP; migration_state tracks parity per identity | Discrepancy rate between the two systems is monitored and must be ~zero before advancing a batch |
| **5. Progressive cutover** | Batch-by-batch (start with lowest-risk employee cohort, e.g. new hires with no legacy Kratos history), redirect authentication traffic to the new IdP; Kratos federation bridge for that batch is turned off | Each batch's fitness-function checks (§10) pass before the next batch starts |
| **6. Kratos freeze → decommission** | Once all batches are cut over, Kratos goes read-only for the compliance-mandated retention period, then is decommissioned | Retention period and decommission are signed off by compliance, not engineering alone |

This phasing is the direct payoff of §6's hook architecture — the same before/after hook mechanism that plugs in external OTP/TOTP/Passkey/Notification providers is what lets the federation bridge and dual-write mode exist without forking the core flow engine.

---

## 8. Fitness functions / non-functional requirements

| Dimension | Target | Notes |
|---|---|---|
| Availability (auth path: login, token issuance) | 99.99% | Measured across Identity Service + Hydra + Permify + CockroachDB as a chain; a single-component SLA higher than the chain's SLA is not sufficient |
| Latency | P99 login-initiation < 300ms; Permify `Check()` P99 < 50ms; OTP/TOTP/Passkey round-trip bounded by the external service's own SLA, not the IdP's | External-service latency must be contracted separately — the IdP cannot make an SLA promise on a call it doesn't control |
| Data residency | 100% of live India-resident data replicas within India-designated CockroachDB super-regions | Verify via CockroachDB's own region-placement introspection, not just config intent |
| Backup encryption | 100% of `BACKUP` jobs specify an explicit KMS/encryption key | Automated CI/ops check — a backup job without this parameter should fail, not warn |
| Tenant isolation | Zero cross-tenant data return across all three independent layers (§4.1): token-claim forgery attempts, RLS-bypass attempts (query without a tenant filter, raw/ad hoc query), and Permify `Check()` denial for any cross-tenant relation probe | Run as a CI gate on every PR touching a repository method or authorization path — not a periodic manual review |
| Credential migration | Zero forced password resets during Kratos migration; 100% of imported credentials verify against at least one live login attempt before a batch is marked complete | Directly required by the "no compromise on regulations" instruction — a forced mass reset would itself be a customer-facing incident |
| Auditability | 100% of authentication and admin actions produce a hash-chained audit record | Sampled tamper-evidence verification on a recurring schedule |

**Explicitly not asserted:** a specific RBI-mandated RTO/RPO figure. This research pass did not verify a specific numeric DR requirement from RBI text for this system class — the bank's compliance/BCP team should supply the binding figure rather than this document inventing one.

---

## 9. Phased implementation roadmap (for AI-coder execution)

Each phase below is scoped to be handed to an AI coding agent as a self-contained epic, with explicit entry/exit criteria so a coding agent (or a human reviewer) can verify completion without re-deriving intent.

**Phase 0 — Foundations**
Entry: none. Exit: multi-region CockroachDB cluster live in India-designated super-regions; Hydra deployed against `hydra` database; Permify deployed against `permify` database; base Terraform/IaC for the public-cloud India-region environment with encryption, network isolation, and logging enabled by default; CI/CD scaffolding.

**Phase 1 — Core Identity Service**
Entry: Phase 0 done. Exit: `idp` database schema (§3) migrated; identity CRUD; credential storage abstraction (password hash only — no OTP/TOTP secret fields exist in code); flow engine skeleton for login/registration/recovery/verification/settings with hook extension points wired but no external providers yet; tenant + tenant_config CRUD.

**Phase 2 — Hydra integration**
Entry: Phase 1 done. Exit: Identity Service implements Hydra's login/consent challenge-accept-reject contract end to end; OAuth client management surfaced per tenant; a full login → consent → token round trip works for at least one native (non-migrated) test tenant.

**Phase 3 — Permify integration**
Entry: Phase 1 done (can run parallel to Phase 2). Exit: Permify schema (entities/relations per §3) deployed; relation-tuple writes triggered on identity/role/org changes; `Check()` enforcement wired into the API Gateway/BFF for at least one protected resource per tenant type.

**Phase 4 — External adapter integration**
Entry: Phase 1 done. Exit: OTP/TOTP/Passkey/Notification adapter interfaces implemented against the bank's actual enterprise services (sandbox/staging endpoints first); per-tenant config resolution proven for at least two tenants pointing at different provider configs; adapters fail closed with no native fallback.

**Phase 5 — Kratos migration bridge**
Entry: Phases 1–4 done. Exit: federation bridge (§9 phase 2) live for a pilot employee cohort with zero behavior change observed; credential import job tested idempotently against a Kratos staging export.

**Phase 6 — Pilot cutover**
Entry: Phase 5 done. Exit: one low-risk employee batch fully migrated (dual-write verified, then cutover); all §10 fitness functions passing for that batch.

**Phase 7 — Progressive cutover, all tenant types**
Entry: Phase 6 done. Exit: remaining employee batches, then retail, then corporate, then partner, then vendor/merchant/NTB tenants migrated in that order (ascending blast-radius sensitivity is deliberately not the same as ascending regulatory sensitivity — retail is high-volume but well-understood; corporate/partner carry the more complex entitlement graphs and should follow, not lead).

**Phase 8 — Compliance hardening**
Entry: can start once Phase 3 and Phase 4 are stable, does not need to wait for full cutover. Exit: WORM audit trail finalized; DPDP consent ledger live; penetration test completed; RBI compliance review completed against the current (re-verified, not assumed) primary regulatory text; DR drill executed against the actual RTO/RPO figures supplied by compliance.

**Phase 9 — Kratos decommission**
Entry: Phase 7 fully complete and the compliance-mandated retention period elapsed. Exit: Kratos infrastructure decommissioned.

---

## 10. Open questions requiring bank input before implementation starts

1. **Cloud provider and exact India regions.** The architecture assumes a public cloud provider with 3+ India regions to satisfy CockroachDB's `REGION` survival goal — confirm which provider and which regions are actually available/approved.
2. **Exact RBI RTO/RPO figures** for this system's criticality tier — not asserted in this document (see §8).
3. **Precise current statutory basis and applicability scope** of the RBI IT-outsourcing Master Directions (2023 and 2025 successor) for this specific bank entity type — the specific claim checked in this research round was refuted (see §11) and needs a fresh legal/compliance verification pass, not an engineering assumption.
4. **Whether any current Kratos-integrated internal system requires SAML2** (not just OIDC) — the blueprint deliberately does not commit to building a SAML bridge until this is confirmed against the actual internal-app inventory.
5. **Permify/FusionAuth roadmap risk.** Permify was acquired by FusionAuth (announced Nov 2025); core Permify and its ReBAC schema language are unchanged as of this research snapshot, but pricing/hosting/tenancy features under FusionAuth ownership should be re-checked before long-term commitment.
6. **Tenant-count / blast-radius guidance at bank scale.** No published Permify guidance was found on tenant-count scaling limits or per-tenant blast-radius containment for the highest-sensitivity tenant class (large corporate/B2B) — worth a direct question to Permify/FusionAuth before finalizing whether row-level tenancy is sufficient for that segment or whether an additional isolation mechanism is warranted for it specifically.

---

## 11. Verification confidence & explicit exclusions

All Ory Hydra, Permify, and CockroachDB technical claims in this document were independently verified 2-1 or 3-0 against primary vendor documentation (GitHub repos, official docs, RFCs) during the research pass, plus independent third-party corroboration. RBI regulatory claims are confirmed at the level of the Directions' existence, dates, and the specific clauses cited in §4 and the blueprint's §4 — but **two adjacent, more specific claims were checked and refuted** and must not be treated as verified:

- ❌ "The 2023 IT Governance Master Direction dedicates a numbered Chapter IV to cyber-incident/VAPT requirements" — refuted 1-2.
- ❌ "The 2023 Outsourcing Master Direction's legal basis is specifically Section 35A of the Banking Regulation Act, 1949, with applicability to commercial banks, UCBs, NBFCs, CICs, and AIFIs" — refuted 1-2.

Both refuted claims are adjacent to confirmed ones (the Directions themselves, their dates, and their substantive data-separation/cloud-policy content are confirmed) — the refutation is about a specific structural/legal detail layered on top, not the Directions' existence. Treat any statement about exact chapter numbering or precise statutory basis as **unverified** until the bank's compliance/legal team re-checks it against the current primary RBI text.

---

## 12. Sources (primary unless noted)

- RBI — IT Governance, Risk, Controls and Assurance Practices Directions, 2023: https://www.rbi.org.in/scripts/BS_ViewMasDirections.aspx?id=12562
- RBI — Master Direction on Outsourcing of IT Services (2023): https://fidcindia.org.in/wp-content/uploads/2023/04/RBI-OUTSOURCING-OF-IT-SERVICES-10-04-23.pdf
- Google Cloud — RBI India compliance mapping (secondary, vendor): https://cloud.google.com/security/compliance/rbi-india
- Ory Hydra (GitHub, primary): https://github.com/ory/hydra
- Ory — OAuth2/OIDC docs (primary): https://www.ory.com/docs/oauth2-oidc
- Ory Kratos — import user accounts/identities (primary): https://www.ory.com/docs/kratos/manage-identities/import-user-accounts-identities
- Ory Kratos — hooks configuration (primary): https://www.ory.com/docs/kratos/hooks/configure-hooks
- Permify — ReBAC use case (primary): https://docs.permify.co/use-cases/rebac
- Permify — multi-tenancy (primary): https://docs.permify.co/use-cases/multi-tenancy
- CockroachDB — multi-region overview (primary): https://www.cockroachlabs.com/docs/stable/multiregion-overview
- CockroachDB — multi-region survival goals (primary): https://www.cockroachlabs.com/docs/stable/multiregion-survival-goals
- CockroachDB — encryption reference (primary): https://www.cockroachlabs.com/docs/stable/security-reference/encryption
- CockroachDB — take and restore encrypted backups (primary): https://www.cockroachlabs.com/docs/stable/take-and-restore-encrypted-backups
- One2N — building multi-tenant authorization with Permify (secondary/blog, corroborating): https://one2n.io/blog/building-multi-tenant-authorization-system-for-b2b-saas-in-go-using-permify
- CockroachDB — Row-Level Security overview (primary, single WebSearch spot-check, not part of the original 110-agent verification pass — re-confirm before hard commitment): https://www.cockroachlabs.com/docs/stable/row-level-security
- CockroachDB — `CREATE POLICY` reference (primary): https://www.cockroachlabs.com/docs/dev/create-policy
