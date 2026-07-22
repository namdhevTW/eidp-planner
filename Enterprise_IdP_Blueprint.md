# Enterprise Identity Provider (IdP) — Requirements Blueprint
**Target audience:** AI coding assistant (Claude Code / proprietary bank AI coder) + engineering team
**Domain:** Top Indian scheduled commercial bank
**Status:** Supersedes the earlier `Enterprise_IdP_Blueprint.md` (git history, commit `4ccad2a`) — that version modeled Ory Hydra only as a *design precedent* behind a hypothetical separate in-house Authorization Server. Current reality: **Ory Hydra is the live OAuth2/OIDC AS and Permify is the live authorization engine** in this ecosystem; this document builds *with* them, not around a stand-in.

---

## 0. Locked context (do not re-derive — confirmed with the bank stakeholder)

| Decision | Answer |
|---|---|
| OAuth2/OIDC provider | **Ory Hydra** — already running, backed by **CockroachDB** |
| Authorization engine | **Permify** (ReBAC/Zanzibar-style) — already running |
| Existing internal identity system | **Ory Kratos**, currently the identity store for internal bank systems |
| Relationship to Kratos | **Migrate.** New IdP becomes the single system of record; Kratos is sunset over time. Migration must not break systems currently integrated with Kratos mid-transition. |
| Deployment target | **Public cloud, India region**, meeting RBI data-residency / outsourcing / critical-infrastructure obligations |
| Tenant populations | Retail banking customers · Internal employees/staff · Corporate/business banking customers (B2B) · Third-party/fintech partners (open banking / AA-style) · Vendors/merchants/NTB (not-yet-a-customer) users |
| OTP generation | **External enterprise service — integrate, do not rebuild.** Per-tenant pluggable. |
| TOTP | **External enterprise service — integrate, do not rebuild.** Per-tenant pluggable. |
| Passkeys/WebAuthn | **External enterprise service — integrate, do not rebuild.** Per-tenant pluggable. |
| Notifications (Email/SMS) | **External enterprise service — integrate, do not rebuild.** Per-tenant pluggable. |
| Data layer | New IdP's own schema should target **CockroachDB**, sharing the HA/operational model already proven for Hydra |
| Deliverable shape | Blueprint + architecture (components, data model, fitness functions) + phase-wise implementation plan — no scaffolding code in this pass |

This flips the biggest assumption in the old plan: the old plan's §1.4 explicitly said *"this IdP does not mint OAuth2 access/refresh tokens... it becomes the authentication backend behind [a separate] existing AS."* That AS **is Hydra**. The new IdP is Hydra's **login/consent provider** — nothing more, nothing less, on the OAuth side — while owning identity, credentials-orchestration, sessions, and per-tenant policy.

---

## 1. Authentication functionalities

- **Core flows:** Login, Registration, Recovery, Verification, Settings (mirrors Kratos's five self-service flows, deliberately — see migration rationale in `ARCHITECTURE_PLAN.md` §9) plus Logout (front-channel + back-channel OIDC logout via Hydra).
- **Credential methods:** Password (fallback only), OTP (SMS/Email, via external enterprise OTP service), TOTP (via external enterprise TOTP service), Passkeys/WebAuthn (via external enterprise Passkey service). The new IdP **never generates, stores, or verifies OTP/TOTP secrets itself** — it orchestrates calls to the external services and stores only references/state (see `ARCHITECTURE_PLAN.md` §8).
- **Step-up / contextual auth:** Risk-signal-driven (new device, geo-velocity, high-value transaction) escalation to a stronger credential method, evaluated per tenant policy.
- **Session management:** Centralized session store (CockroachDB-backed with a fast cache tier), configurable absolute/idle timeouts per tenant, immediate global invalidation.
- **Account recovery:** Self-service, MFA-gated, rate-limited against enumeration.

## 2. Multi-tenancy

- **Model:** Shared-schema, row-level `tenant_id` isolation — deliberately matched to **Permify's own documented multi-tenancy pattern** (single shared instance, mandatory `tenant_id` on nearly every API call, row-level `tenant_id` column on relation-tuple and schema tables). Running a different isolation model in the IdP than in Permify would create an isolation seam at every authorization check; this is avoided by design.
- **Tenant types:** Retail, Employee (internal), Corporate/Business (B2B), Partner (fintech/open-banking), Vendor/Merchant/NTB.
- **Per-tenant configuration:** Branding, password policy, session lifetimes, MFA enforcement rules, and — critically — **which external OTP/TOTP/Passkey/Notification provider endpoint to call**, resolved at runtime from tenant config.
- **Corporate/B2B entitlement hierarchies:** Modeled in Permify using relation-based inheritance (parent/owner relations with cascading permissions), not flattened into a role table inside the IdP itself.

## 3. Security

- **Transport:** TLS 1.3 only, strict cipher suites.
- **At rest:** CockroachDB Encryption at Rest (AES, all key sizes) for the live cluster; **backups require explicit separate encryption/KMS configuration at backup time** — CockroachDB's cluster-wide EAR does not automatically encrypt `BACKUP` output. This is a concrete operational gate, not a nice-to-have.
- **Credential storage:** Password hashes only (Argon2id/PBKDF2-class), no OTP/TOTP secrets held natively — reduces the IdP's own sensitive-data footprint, since those secrets live in the external enterprise services.
- **Token security:** Hydra owns OAuth2/OIDC token issuance — asymmetric signing, short-lived access tokens, rotatable refresh tokens. The new IdP never mints app-facing OAuth tokens itself.
- **Cross-tenant access:** Enforced twice — Permify `Check()` at the authorization layer, and mandatory `tenant_id` scoping at every IdP data-access path — so a bug in one layer doesn't collapse tenant isolation.
- **Data residency:** CockroachDB multi-region topology constrained to India-designated regions via **super-regions**, satisfying data-localization/domiciling obligations for the cluster's live data (backups handled separately, per above).

## 4. Compliance (Indian banking context)

- **Regulatory anchors (verified against primary RBI text during research):** RBI's IT Governance, Risk, Controls and Assurance Practices Directions, 2023 (effective 1 Apr 2024) — vendor/outsourcing risk-assessment obligations extend to cloud-hosted systems; RBI's Master Direction on Outsourcing of IT Services (2023) and its 2025 successor — multi-tenant cloud data-separation requirements, an explicit cloud-adoption policy addressing data sovereignty, and governance over provider evaluation/exit strategy.
- **Explicit caution:** Two adjacent, more specific claims were checked during research and **did not hold up** — (a) a claim that the 2023 IT Governance Direction has a numbered "Chapter IV" specifically for cyber-incident/VAPT requirements, and (b) a claim about the precise statutory basis (Section 35A of the Banking Regulation Act) and applicability list of the Outsourcing Direction. **Do not cite either of those specifics in a compliance filing** — re-verify the exact chapter/section numbering and statutory basis against the current primary RBI text (and note the 2025 successor Direction has already superseded parts of the 2023 one) before any compliance sign-off.
- **DPDP Act 2023:** Consent management (purpose-scoped, withdrawable), data minimization, right to erasure, breach notification — implemented as a dedicated consent ledger, separate from Hydra's OAuth consent grants (see `ARCHITECTURE_PLAN.md` §5).
- **Audit:** Immutable, tamper-evident audit trail for authentication and administrative actions.

## 5. Monitoring & observability

- Distributed tracing (OpenTelemetry) across API Gateway → IdP → Hydra → Permify → external provider adapters.
- Metrics: login success/fail rates, MFA latency per provider, Permify `Check()` latency, CockroachDB replication/region-health.
- Structured logs with PII masked before leaving the service boundary, forwarded to centralized SIEM.

## 6. Ecosystem & infrastructure topology

- Public cloud, India region(s), multi-region CockroachDB cluster shared by Hydra, the new IdP, and Permify's storage layer, using CockroachDB's `REGION` survival goal and super-regions for both HA and data-domiciling.
- Kubernetes-orchestrated stateless services (Identity Service, adapters, gateway) for horizontal scale.
- Event bus (Kafka) for async cross-system events (`identity.migrated`, `login.failed`, `consent.granted`) — used heavily during the Kratos migration window.

## 7. Standards & extensibility

- OIDC/OAuth2 via Hydra for modern apps; SAML2 bridging only if a legacy internal app strictly requires it (evaluate against actual internal-app inventory before building).
- API-first, headless: the new IdP is Hydra's login/consent provider and nothing renders a bank-branded UI itself beyond that contract.
- Extension points: a hook/webhook system on each self-service flow (login/registration/recovery/verification/settings), modeled deliberately on Kratos's own before/after hook mechanism — this is what makes the OTP/TOTP/Passkey/Notification providers swappable per tenant without touching core flow code, and what makes the Kratos migration bridge tractable.

See `ARCHITECTURE_PLAN.md` for the detailed architecture, data model, migration plan, fitness functions, and phased implementation roadmap.
