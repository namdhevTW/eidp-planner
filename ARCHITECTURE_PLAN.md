# Enterprise IdP — Architecture & Implementation Plan
**For:** Top Indian Bank — Retail, Corporate/Wealth, and Internal (Employee) IAM
**Source requirements:** `Enterprise_IdP_Blueprint.md`
**Architectural precedent:** Ory Kratos, WSO2 Identity Server, Ping Identity (PingFederate/PingOne), Keycloak, Ory Hydra (auth-delegation pattern)
**Status:** Decisions locked (§1) — architecture reflects sign-off

---

## 0. How to read this document

Every non-trivial design choice below cites which battle-tested IdP it's modeled on and why, plus a primary-source link. Where the frameworks disagree (they often do), §1 calls out the fork explicitly instead of silently picking a side.

---

## 1. Decisions — locked

### 1.1 Build approach — **Custom build, patterns borrowed from OSS IdPs**
Bespoke services, but data models/flow engines copy proven designs from Kratos/Keycloak/WSO2/Ping rather than reinventing them. Rationale: the blueprint's hardest requirements — India-only data residency, tamper-evident WORM audit trails, synchronous core-banking/e-KYC callouts — are exactly where OSS/commercial IdPs are least flexible. Borrowing their data models de-risks the parts that are genuinely solved problems (credential storage, flow state machines) without inheriting their constraints on the parts that aren't.

### 1.2 Primary tech stack — **Go**
Matches Ory Kratos's own stack: stateless-by-default services, trivial horizontal scaling ("just spin up another container" — [ory.com/docs/kratos/guides/production](https://www.ory.com/docs/kratos/guides/production)), low memory footprint per instance, strong concurrency primitives for the fan-out to MFA providers/risk predictors/webhooks that every login touches. Standardize on `net/http` + a thin router (chi/echo), `pgx` for Postgres, `go-redis`, and `sigs.k8s.io` tooling for k8s-native deployment.

### 1.3 Multi-tenant isolation model
- **Retail / Wealth tenants:** shared schema, `tenant_id` column on every table + **Postgres Row-Level Security (RLS)** as defense-in-depth beneath API-Gateway RBAC/ABAC — mirrors WSO2 IS's `TENANT_ID`-column model ([is.docs.wso2.com — multitenancy](https://is.docs.wso2.com/en/6.1.0/references/concepts/introduction-to-multitenancy/)).
- **Corporate/high-compliance tenants AND Internal (Employee) IAM:** dedicated Postgres **schema-per-tenant** within the same cluster — closer to Keycloak's realm boundary ([keycloak.org — core concepts](https://www.keycloak.org/docs/latest/server_admin/index.html#core-concepts-and-terms)). Employee IAM is treated as a high-compliance tenant by default: it's the blast-radius-critical tenant, since compromise there means access to admin tooling across every other tenant.
- **Sub-tenant grouping** (branches, business units within a corporate tenant): modeled as **Populations**/**Groups** (PingOne's term), not new tenants — a user belongs to exactly one population but many groups ([docs.pingidentity.com — groups vs populations](https://docs.pingidentity.com/pingone/directory/p1_groups_vs_populations.html)). Avoids tenant-count explosion.

### 1.4 OAuth2 token issuance — **delegated to the bank's existing in-house Authorization Server**
The bank already operates an in-house OAuth2/OIDC Authorization Server that provisions access/refresh tokens for apps enterprise-wide. This new IdP does **not** duplicate that — it does not mint OAuth2 access/refresh tokens, does not manage `oauth_client` registrations, and does not run a JWKS/introspection/revocation endpoint for app-facing tokens. Instead, this IdP becomes the **authentication backend behind** the existing AS.

This is exactly the split Ory uses between **Hydra** (OAuth2/OIDC AS, "without user management... connects to any existing identity provider through a login and consent app" — [github.com/ory/hydra](https://github.com/ory/hydra)) and **Kratos** (identity/credentials/MFA). Hydra's documented contract ([ory.com/docs/oauth2-oidc/custom-login-consent/flow](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow)):
1. AS redirects the browser to the login provider with an opaque `login_challenge`.
2. Login provider authenticates the user via its own mechanism (here: our Auth/Flow Service — password/OTP/MFA/step-up).
3. Login provider calls the AS's admin API to **accept** (`subject`, `acr`, `remember`, `remember_for`, `context`) or **reject** the login request; browser is redirected back to the AS with a verifier.
4. AS proceeds to its own consent step and mints tokens itself.

**Our IdP implements the login-provider side of this contract** against the bank's specific in-house AS (its actual challenge/accept/reject API shape will differ from Hydra's — see §3.6 for the adapter design that isolates that difference). We keep our own `session`/AAL model (§4.4) for our own SSO/step-up UX, and surface `acr` (derived from AAL) to the AS on accept — but the AS, not us, is the source of truth for app-facing OAuth2 tokens.

---

## 2. Reference architecture — requirement → precedent → design choice

| Blueprint requirement | Precedent it's modeled on | Design choice |
|---|---|---|
| Passwordless/biometric-first login, password fallback | Ory Kratos self-service flows ([ory.com/docs/kratos/self-service](https://www.ory.com/docs/kratos/self-service)) | Flow-state-machine login (§3.2), method priority ordered per tenant policy |
| MFA: SMS/Email OTP, TOTP, FIDO2/WebAuthn | Kratos `CredentialsType` enum incl. `webauthn`, `totp`, `code`, `lookup_secret` ([github.com/ory/kratos — credentials.go](https://github.com/ory/kratos/blob/master/identity/credentials.go)); Keycloak `CREDENTIAL` table pattern | Credential table keyed by `(identity_id, type)`, §4.2 |
| Contextual/step-up auth on risk signals | Keycloak conditional authentication sub-flows ([keycloak flows doc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/authentication/flows.adoc)); PingOne Protect risk predictors + mitigation rules ([docs.pingidentity.com — risk evaluations](https://docs.pingidentity.com/pingone/threat_protection_using_pingone_protect/p1_protect_risk_evaluations.html)); WSO2 adaptive-auth scripting ([is.docs.wso2.com — adaptive auth JS API](https://is.docs.wso2.com/en/6.0.0/references/adaptive-authentication-js-api-reference/)) | Policy-as-data flow tree (REQUIRED/ALTERNATIVE/CONDITIONAL executions) + externally-scored risk engine, §3.4 |
| Federating a corporate tenant's own Azure AD | Keycloak Identity Brokering (distinct from User Federation) ([keycloak — identity brokering](https://www.keycloak.org/docs/latest/server_admin/index.html)); WSO2 Federated Authenticator + IdP config object with claim mapping ([is.docs.wso2.com — federated authenticator](https://is.docs.wso2.com/en/6.0.0/guides/identity-federation/federated-authenticator/)) | Per-tenant `identity_provider` config row, protocol adapter pattern, §3.5 |
| Session store with immediate invalidation | Kratos session model (`active`, `expires_at`, `authenticator_assurance_level`, `devices[]`) ([ory.com/docs/kratos/session-management](https://www.ory.com/docs/kratos/session-management/overview)); Keycloak Infinispan session caches | Redis-backed session, AAL field, §4.3 |
| Custom IdP per corporate tenant, SAML2 for legacy apps | PingFederate IdP/SP connections + protocol-per-connection model ([docs.pingidentity.com — IdP connections](https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_manag_idp_connect.html)) | Federation Service supports SAML2 + OIDC concurrently, §3.5 |
| OAuth2 token issuance owned by an existing enterprise AS; this IdP only authenticates users | Ory Hydra login_challenge/consent_challenge delegation — Hydra explicitly ships "without user management," delegating to an external login provider ([github.com/ory/hydra](https://github.com/ory/hydra), [flow docs](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow)) | Auth-Delegate Adapter implements the login-provider side of the bank's in-house AS's challenge contract, §3.6 |
| Extensibility hooks to core banking/SMS gateway | Kratos before/after webhooks with blocking 4xx-abort semantics ([ory.com/docs/kratos/hooks](https://www.ory.com/docs/kratos/hooks/configure-hooks)); PingOne DaVinci Flow Conductor async callout ([docs.pingidentity.com — flow conductor](https://docs.pingidentity.com/connectors/flow_conductor_connector.html)) | Synchronous blocking webhook for KYC-gating + async Kafka event for everything else, §3.7 |
| API-first, headless, custom bank frontend | Kratos BYOUI model, strict Public/Admin API network split ([ory.com/docs/network/kratos/intro](https://www.ory.com/docs/network/kratos/intro)) | Public API (internet-facing) / Admin API (internal-only, mTLS) split, §3.1 |
| Claims/attributes per tenant, SCIM provisioning | WSO2 claim dialects (namespace-scoped claim URIs, store-independent) ([is.docs.wso2.com — claim dialects](https://is.docs.wso2.com/en/5.10.0/learn/configuring-claim-dialects/)) | `claim_dialect` + `claim_mapping` tables, §4.5 |

---

## 3. Service architecture (clean/hexagonal)

Each service below is internally structured as **ports-and-adapters**: a domain core (pure business rules, no framework types) behind inbound ports (REST/gRPC controllers) and outbound ports (repository interfaces, external gateway interfaces), with adapters plugged in at the edges. This is what makes "custom-build but borrow the data model" tractable — the domain core is small and testable regardless of which framework's schema inspired it.

```
                        ┌────────────────────┐
   Internet ───────────▶│   API Gateway       │  RBAC/ABAC enforcement, rate limiting,
                        │  (Kong/Envoy/APIM)  │  WAF, per-tenant routing
                        └─────────┬────────────┘
                                  │
        ┌─────────────────────────┼──────────────────────────────┐
        ▼                         ▼                              ▼
┌───────────────┐        ┌────────────────┐            ┌──────────────────┐
│ Identity Svc   │        │ Auth/Flow Svc  │            │ Federation Svc    │
│ (traits, CRUD) │        │ (login/reg/    │            │ (SAML2/OIDC       │
│                │        │  recovery flow │            │  broker, JIT      │
│                │        │  state machine)│            │  provisioning)    │
└───────┬────────┘        └───────┬────────┘            └────────┬──────────┘
        │                         │                              │
        ▼                         ▼                              ▼
┌───────────────┐        ┌────────────────┐            ┌──────────────────┐
│ Credential Svc │        │ MFA/Risk Svc   │            │ Auth-Delegate     │
│ (password/     │        │ (TOTP/WebAuthn │            │ Adapter           │
│  OTP/WebAuthn) │        │  /risk scoring)│            │ (speaks the       │
│                │        │                │            │  in-house AS's    │
└───────┬────────┘        └───────┬────────┘            │  login/consent    │
        │                         │                     │  challenge API)   │
        ▼                         ▼                     └────────┬──────────┘
┌───────────────┐        ┌────────────────┐                      │
│ Session Svc    │        │ Consent Svc    │                      ▼
│ (Redis-backed) │        │ (DPDP consent  │            ┌──────────────────┐
│                │        │  ledger)       │            │ Bank's existing   │
└───────────────┘        └────────────────┘            │ in-house OAuth2/  │
                                                          │ OIDC Authorization│
┌───────────────┐                                        │ Server (owns app- │
│ Audit Svc      │                                        │ facing tokens)    │
│ (WORM, hash-   │                                        └──────────────────┘
│  chained)      │
└───────────────┘

  Cross-cutting: Notification Gateway (SMS/Email/Push abstraction over
  telecom/SendGrid providers) · Admin/Config Svc (tenant policy CRUD) ·
  Kafka event bus (user.registered, login.failed, mfa.challenged, ...)
```

### 3.1 API surface split (Kratos-derived)
- **Public API** (internet-facing, per-tenant subdomain or path prefix): flow init/submit, `/sessions/whoami`, the login-provider endpoint the in-house AS redirects to (§3.6), and SAML SSO endpoints for legacy apps that federate directly. No OAuth2 authorize/token/userinfo endpoints here — those live on the existing in-house AS (§1.4). Rate-limited, WAF-fronted.
- **Admin API** (internal network / mTLS only, never internet-exposed — explicit Kratos production guidance: [ory.com/docs/kratos/guides/production](https://www.ory.com/docs/kratos/guides/production)): identity CRUD, bulk import, tenant config, impersonation-for-support (fully audited).

### 3.2 Auth/Flow Service — flow state machine (Kratos-derived)
Flow object: `{id (UUID), tenant_id, type (login|registration|recovery|verification|settings), state, expires_at, ui.nodes[], methods_available[]}`. Client inits a flow → gets flow id + form schema → submits to flow action URL → service validates, either returns flow with field errors or completes (issues session or redirects).

Two flow **modes**, per Kratos's explicit browser-vs-API distinction ([ory.com/docs/kratos/self-service](https://www.ory.com/docs/kratos/self-service)): **Browser mode** (cookie + CSRF token) for server-rendered/cookie-based web; **API mode** (bearer session token, no cookie) for native mobile apps.

### 3.3 Authentication policy — flow tree (Keycloak-derived)
Per-tenant authentication policy is a **tree of executions**, each with a requirement: `REQUIRED` | `ALTERNATIVE` | `CONDITIONAL` | `DISABLED`, mirroring Keycloak's authenticator flow model ([keycloak flows doc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/authentication/flows.adoc)). Conditions inside a `CONDITIONAL` sub-flow are AND-ed (Keycloak's documented limitation — OR requires nested sub-flows); we adopt the same limitation rather than building a full expression engine, to keep the executor auditable.

Example tree for a Retail tenant's high-value transaction step-up:
```
REQUIRED: password-or-biometric
CONDITIONAL (if risk_score >= HIGH):
  REQUIRED: step_up_totp_or_webauthn
CONDITIONAL (if new_device AND geo_velocity_flag):
  REQUIRED: sms_otp_verification
```

### 3.4 MFA/Risk Service
- Factor types: `sms_otp`, `email_otp`, `totp`, `webauthn` (FIDO2), matching the blueprint. Modeled after PingOne's device-pairing model — a user can pair **multiple devices**, and policy chooses default-device vs user-selects ([docs.pingidentity.com — manage devices](https://docs.pingidentity.com/pingone/directory/p1_manage_a_users_devices.html)).
- Risk scoring: pluggable predictors (new-device, geo-velocity, IP reputation, transaction-value threshold) each scored, aggregated into Low/Medium/High — directly modeled on PingOne Protect's predictor→score→risk-level pipeline ([docs.pingidentity.com — risk policy](https://docs.pingidentity.com/pingone/threat_protection_using_pingone_protect/p1_protect_adding_risk_policy.html)). Mitigation rules evaluate top-to-bottom, first match wins.
- WebAuthn/FIDO2 per W3C spec ([w3.org/TR/webauthn-3](https://www.w3.org/TR/webauthn-3/)); relying-party ID scoped per tenant custom domain.

### 3.5 Federation Service
- Distinguishes **User Federation** (delegate credential *validation* to external LDAP/AD, no password import) from **Identity Brokering** (bank IdP acts as SP to external OIDC/SAML IdP, e.g., a corporate tenant's Azure AD) — Keycloak's explicit distinction ([keycloak — identity brokering](https://www.keycloak.org/docs/latest/server_admin/index.html)).
- Per-tenant `identity_provider` config: protocol, endpoints, signing certs, **claim mapping table** (external claim → internal claim URI), matching WSO2's IdP config + claim-mapping model ([is.docs.wso2.com — federated authenticator](https://is.docs.wso2.com/en/6.0.0/guides/identity-federation/federated-authenticator/)).
- First-broker-login flow: review-profile step + account-linking-by-verified-email, per Keycloak's first-broker-login pattern ([keycloak — first login flow](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/identity-broker/first-login-flow.adoc)).

### 3.6 Auth-Delegate Adapter (to the existing in-house Authorization Server)
This replaces a from-scratch Token/AS Service (§1.4). The bank's existing in-house AS owns OAuth2/OIDC token issuance, JWKS, introspection, and revocation for app-facing tokens — this IdP is the **login provider** it delegates authentication to, following Ory Hydra's login_challenge/consent_challenge contract ([ory.com/docs/oauth2-oidc/custom-login-consent/flow](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow)) as the reference shape:

1. **Inbound:** the in-house AS redirects the user's browser to this IdP's public login endpoint with an opaque challenge parameter (`?login_challenge=...` in Hydra's shape — the bank's AS may name it differently). The adapter resolves the challenge against the AS's admin API to fetch context (client_id, requested scope, whether the subject is already known and login can be `skip`ped).
2. **Runs our own flow:** the challenge is stored as correlation context on a `login_request` row (§4.6) linked to an Auth/Flow Service flow — from here it's an ordinary login/MFA/step-up flow (§3.2–3.4), independent of the AS's protocol details.
3. **Outbound accept/reject:** on success, the adapter calls the AS's accept-login equivalent with `{subject, acr, remember, remember_for, context}` — `subject` is our `identity.id` (or a stable external-facing alias if the AS requires one), `acr` is derived from the session's AAL (§4.4: `aal1`→basic, `aal2`→MFA-verified, `aal3`→hardware-key). On failure/abandonment, it calls reject. The AS then proceeds to its own consent step and mints tokens — out of this IdP's scope entirely.
4. **Isolating the AS's actual API shape:** because "the bank's existing in-house AS" is not Hydra and its exact challenge/accept/reject contract is bank-specific, this is built as a **port-and-adapter**: the Auth/Flow Service's domain core only knows "authentication succeeded for identity X with ACR Y, notify the delegator" — a single adapter implementation translates that into the AS's actual HTTP contract. If the AS's contract changes, only the adapter changes.
5. **Direct SAML2 for legacy apps that don't go through the in-house AS at all** (per blueprint's SAML2-for-legacy requirement) is still served directly by the Federation Service (§3.5) acting as SAML IdP — the delegation pattern above only applies to the OAuth2/OIDC path that already flows through the existing AS.
6. **Latency/reliability:** the accept/reject call to the AS's admin API is now a hard synchronous dependency on the critical path of every login — needs a circuit breaker, tight timeout (target <300ms p99), and a clear fallback (fail the login, don't silently retry against a state-mutating endpoint) since accept-login is not idempotent by nature (single-use challenge, per Hydra's model — [ory security architecture](https://www.ory.com/docs/hydra/security-architecture)).

### 3.7 Extensibility hooks
- **Synchronous blocking webhook** (registration/settings flows only, e.g., core-banking account-number validation, e-KYC/Aadhaar check): configured with strict timeout (recommend 5–10s, tighter than Kratos's documented ~30s default given a real-time UX budget); non-2xx response aborts the flow with structured field errors, per Kratos's webhook semantics ([ory.com/docs/guides/integrate-with-ory-cloud-through-webhooks](https://www.ory.com/docs/guides/integrate-with-ory-cloud-through-webhooks)).
- **Async fire-and-forget** (everything else — analytics, downstream provisioning, fraud-engine notification): published to Kafka, consumed by the target system; no flow blocking.
- **Long-running async with resume** (e.g., a document-verification step that a human reviews out-of-band): modeled on PingOne DaVinci's Flow Conductor "challenge variable" pattern — flow suspends, a callback resolves it later ([docs.pingidentity.com — flow conductor](https://docs.pingidentity.com/connectors/flow_conductor_connector.html)).

---

## 4. Data model

All tables carry `tenant_id` (except where noted as tenant-config tables themselves) and are subject to Postgres RLS. UUIDv7 recommended for primary keys (time-ordered, index-friendly, unlike UUIDv4).

### 4.1 `tenant`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `slug` | text unique | subdomain/path segment |
| `type` | enum | `retail`, `wealth`, `corporate`, `internal` |
| `isolation_tier` | enum | `shared_schema`, `dedicated_schema` |
| `schema_name` | text nullable | set when `isolation_tier = dedicated_schema` |
| `branding_config` | jsonb | logos, theme, email templates |
| `password_policy` | jsonb | |
| `session_policy` | jsonb | absolute/idle timeouts |
| `mfa_policy_id` | FK → `mfa_policy` | |
| `created_at`, `updated_at` | timestamptz | |

*Precedent:* Keycloak realm (branding/password-policy/keys are realm-scoped: [keycloak core concepts](https://www.keycloak.org/docs/latest/server_admin/index.html#core-concepts-and-terms)) + WSO2 shared-schema tenant model + PingOne Organization→Environment hierarchy.

### 4.2 `identity`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | immutable |
| `tenant_id` | FK | |
| `schema_id` | text | which JSON-Schema validates `traits` (retail-customer vs employee vs corporate-user schema) — Kratos's Identity Schema concept ([ory — identity schema](https://www.ory.com/docs/kratos/manage-identities/identity-schema)) |
| `traits` | jsonb | self-service-editable profile (name, email, phone, DOB) — validated against `schema_id` on write |
| `state` | enum | `active`, `suspended`, `locked`, `pending_verification` |
| `kyc_status` | enum | `pending`, `verified`, `rejected` — bank-specific, not in any reference IdP |
| `metadata_public` | jsonb | visible to the identity itself, not user-editable |
| `metadata_admin` | jsonb | admin/support-only |
| `created_at`, `updated_at` | timestamptz | |

*Precedent:* Kratos `Identity` struct — traits vs credentials vs metadata_public/admin split ([github.com/ory/kratos/identity/identity.go](https://github.com/ory/kratos/blob/master/identity/identity.go), [ory — managing identities metadata](https://www.ory.com/docs/kratos/manage-identities/managing-users-identities-metadata)).

### 4.3 `credential`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `identity_id` | FK | |
| `type` | enum | `password`, `totp`, `webauthn`, `sms_otp`, `email_otp`, `lookup_recovery_codes`, `oidc_federated`, `saml_federated` |
| `identifier` | text nullable | unique per `(tenant_id, type, identifier)` — e.g. email for `password`, external subject for `oidc_federated` |
| `credential_data` | jsonb | algorithm/config (non-secret): e.g. Argon2id params, WebAuthn public key + counter |
| `secret_data` | jsonb encrypted | hash + salt, envelope-encrypted with tenant DEK (AES-256, KMS-managed) |
| `device_label` | text nullable | user-facing device name for WebAuthn/TOTP |
| `created_at`, `last_used_at` | timestamptz | |

*Precedent:* directly modeled on Keycloak's `CredentialModel` (`credentialData`/`secretData` JSON split) ([keycloak PasswordHashProvider](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/credential/hash/PasswordHashProvider.html)) and Kratos's `map[CredentialsType]Credentials` per-identity model ([github.com/ory/kratos/identity/credentials.go](https://github.com/ory/kratos/blob/master/identity/credentials.go)). Hashing: **Argon2id**, the Keycloak 25+ default chosen specifically for GPU/side-channel resistance ([keycloak 25 release notes](https://www.keycloak.org/2024/06/keycloak-2500-released)) — matches blueprint's Argon2id/PBKDF2 requirement directly.

### 4.4 `session`
Primary store: **Redis** (hash per session id, TTL = absolute timeout) for immediate invalidation; async-replicated to Postgres `session_audit` (append-only) for compliance trail.

| Field | Notes |
|---|---|
| `id` | session token/cookie value |
| `identity_id`, `tenant_id` | |
| `aal` | `aal1` (one factor) / `aal2` (MFA) / `aal3` (hardware-key) — Kratos AAL model ([ory — session management](https://www.ory.com/docs/kratos/session-management/overview)) |
| `authentication_methods` | list of `{method, completed_at, aal}` |
| `issued_at`, `expires_at` (absolute), `idle_expires_at` | per-tenant policy from `tenant.session_policy` |
| `device` | `{ip, geo, user_agent, device_fingerprint}` |
| `revoked_at` | nullable — set on explicit logout / global-logout / admin action |

*Precedent:* Kratos session object fields ([ory — session management](https://www.ory.com/docs/kratos/session-management/overview)); Redis as the store (not Postgres-primary) is the bank blueprint's own explicit requirement, reinforced by Keycloak's use of a distributed in-memory grid (Infinispan) for the same reason ([keycloak caching](https://www.keycloak.org/server/caching)).

### 4.5 `claim_dialect` / `claim_mapping`
- `claim_dialect(id, tenant_id nullable, namespace_uri)` — `tenant_id null` = shared/system dialect.
- `claim_mapping(id, identity_provider_id, external_claim, internal_claim_uri)` — used by Federation Service to translate incoming SAML/OIDC claims.

*Precedent:* WSO2 claim dialects — store-independent, namespace-scoped claim URIs ([is.docs.wso2.com — claim dialects](https://is.docs.wso2.com/en/5.10.0/learn/configuring-claim-dialects/)).

### 4.6 `login_request` (correlates our flow to the in-house AS's challenge)
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | internal |
| `external_login_challenge` | text | the AS-issued challenge/verifier we're resolving — single-use |
| `tenant_id` | FK | |
| `flow_id` | FK → Auth/Flow Service flow | drives the actual login/MFA UI |
| `identity_id` | FK nullable | set once authenticated |
| `acr` | text nullable | derived from session AAL at accept-time |
| `status` | enum | `pending`, `accepted`, `rejected`, `expired` |
| `created_at`, `completed_at` | timestamptz | |

*Precedent:* directly modeled on Hydra's login_challenge/login_request object — a short-lived, single-use, opaque correlation id ([ory — custom login/consent flow](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow)). No `oauth_client`/`refresh_token`/access-token tables exist in this schema — those are the existing in-house AS's responsibility (§1.4).

### 4.7 `relying_party`
`id, tenant_id, protocol (in_house_as_login_delegate | saml2_sp), display_name, endpoint_config jsonb (challenge-resolve URL, accept/reject URLs, trust cert/secret ref), created_at`. Represents (a) the bank's in-house AS as the primary consumer of our login-provider contract, and (b) any legacy apps that federate to us directly as a SAML2 IdP without going through the in-house AS.

### 4.8 `identity_provider` (federation config, per-tenant)
`id, tenant_id, protocol (saml2|oidc), display_name, metadata_url_or_xml, signing_cert, client_id/secret (oidc), attribute_mapping_id`.

### 4.9 `consent`
DPDP-driven: `id, identity_id, purpose_code, policy_version, granted_at, revoked_at, consent_manager_ref`. Retained per DPDP Rules 2025's consent-audit-trail requirement (Consent Managers must retain records ≥7 years — [DPDP Rules 2025](https://www.dpdpa.com/DPDP_Rules_2025_English_only.pdf)).

### 4.10 `audit_log`
Append-only, hash-chained (`prev_hash`, `record_hash`) for tamper-evidence, mirrored to WORM object storage (India region). `id, tenant_id, actor_identity_id, actor_type (user|admin|system), action, resource_type, resource_id, ip, user_agent, occurred_at, prev_hash, record_hash`. Partitioned by month for retention/archival.

*Note:* no reference IdP in our research ships hash-chained WORM audit natively (Keycloak's admin-events table is a plain audit log, not tamper-evident) — this is bank-specific and must be custom-built.

### 4.11 `risk_signal`
`id, identity_id, session_id nullable, signal_type (new_device|geo_velocity|ip_reputation|txn_value), score, evaluated_at, context jsonb`. Feeds the MFA/Risk Service's mitigation-rule evaluation (§3.4).

---

## 5. Multi-tenant security enforcement

1. **API Gateway layer:** every request must carry a tenant-scoped access token; gateway validates `tenant_id` claim matches the target tenant's route before forwarding (RBAC/ABAC, per blueprint §3).
2. **Service layer:** every repository call is scoped by `tenant_id` extracted from the authenticated context — never taken from a request parameter.
3. **DB layer (defense-in-depth):** Postgres RLS policy `USING (tenant_id = current_setting('app.tenant_id')::uuid)` on every shared-schema table; the service sets `app.tenant_id` per-connection/per-transaction from the validated JWT claim, so even a bug in service-layer scoping can't leak cross-tenant rows.
4. **Corporate dedicated-schema tenants:** additionally isolated by Postgres `search_path`/schema boundary — a compromised shared-schema query literally cannot address these tables.

---

## 6. Performance & scaling strategy

- **Stateless services, stateful stores.** All application services (Identity, Auth/Flow, Federation, MFA/Risk, Auth-Delegate Adapter) are horizontally scalable with no local state — session/flow state lives in Redis, everything durable lives in Postgres — following Kratos's explicit "no additional requirements for scaling... just spin up another container" model ([ory — production guide](https://www.ory.com/docs/kratos/guides/production)).
- **Redis Cluster:** sessions, flow state (short TTL, ~15–60 min), OTP throttling counters, `login_request` correlation entries (short TTL, matching challenge expiry), per-tenant rate-limit counters.
- **Postgres:** primary + India-region read replicas; PgBouncer connection pooling; `audit_log` and `session_audit` partitioned by month; heavy-read config/claims tables (tenant config, claim dialects) cached read-through in Redis with short TTL + explicit invalidation on admin write.
- **Kafka:** async event bus for `user.registered`, `login.failed`, `login.succeeded`, `mfa.challenged`, `session.revoked` — decouples the hot auth path from downstream fraud-engine/SIEM/provisioning consumers, per blueprint §6.
- **The Auth-Delegate Adapter's call to the in-house AS is now the tightest latency budget in the system** (§3.6): every login makes one synchronous outbound call to accept/reject the challenge. Mitigate with connection pooling/keep-alive to the AS, a circuit breaker (fail fast rather than queue logins behind a degraded AS), and treating that call's p99 latency as a first-class SLO metric, not an afterthought — unlike the JWT-validation path in WSO2's or Kratos's own reference architectures, this dependency can't be made DB-free because token issuance now lives outside this IdP entirely (§1.4).
- **Multi-region active-active (Mumbai + Hyderabad, per blueprint §6):** Postgres via synchronous replication within a metro pair is too slow for write-heavy auth paths at 99.99% SLA; recommend **Patroni-managed Postgres with regional read replicas + async cross-region replication**, and route writes to the region owning that tenant's primary ("closest region" affinity per tenant), matching the WSO2 published multi-region pattern of active/passive DC pairs with DNS failover rather than synchronous cross-DC writes ([WSO2 — multi-region deployment](https://wso2.com/library/articles/2018/04/multi-region-deployment-for-wso2-identity-server-part-1/)). Redis Cluster similarly runs per-region with async replication for session data (sessions are re-derivable via token refresh on failover, so losing a few seconds of session writes on regional failover is an acceptable trade-off vs synchronous latency cost).
- **No silent scale caps:** rate limits and connection pool sizes must be tenant-aware (a Corporate tenant's batch operations shouldn't starve Retail's login traffic) — implement via per-tenant token buckets at the gateway, not a single global limiter.

---

## 7. Standards & compliance mapping

| Area | Standard/Regulation | Citation | Design response |
|---|---|---|---|
| Federation | OAuth 2.0 / OIDC Core | RFC 6749; openid.net/specs | Owned by the bank's existing in-house AS; this IdP is its login-provider delegate — Auth-Delegate Adapter, §3.6 |
| Federation | SAML 2.0 | OASIS SAML 2.0 Core | Federation Service, §3.5 |
| MFA hardware/biometric | FIDO2/WebAuthn | [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) | MFA/Risk Service, §3.4 |
| Password hashing | Argon2id | Keycloak 25+ default, chosen for GPU/side-channel resistance ([keycloak 2500 release](https://www.keycloak.org/2024/06/keycloak-2500-released)) | `credential.secret_data`, §4.3 |
| MFA for payments | RBI Master Direction on Digital Payment Security Controls, 2021 — dynamic/non-replicable factor requirement | [rbidocs.rbi.org.in MD](https://rbidocs.rbi.org.in/rdocs/notification/PDFs/MD7493544C24B5FC47D0AB12798C61CDB56F.PDF) | Step-up policy tree, §3.3 |
| Session timeout | Same MD, §52 — auto-terminate on inactivity | same | `tenant.session_policy.idle_timeout`, §4.4 |
| First-login password change | Same MD, §53 | same | forced-rotation flag on `credential` |
| Fraud/anomaly monitoring | Same MD, §37 — geo/IP/velocity/behavioral monitoring | same | `risk_signal` table + MFA/Risk Service, §4.11 |
| Cipher/key strength | RBI Master Direction on IT Governance, 2023 | [rbi.org.in MD IT Governance](https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12562) | TLS 1.3-only, RS256/ES256 signing (no deprecated algs) |
| Incident reporting to CERT-In/RBI | Same MD, Ch. IV §27; Cyber Security Framework for Banks 2016 | [rbi.org.in circular NT41802062016](https://www.rbi.org.in/commonman/Upload/English/Notification/PDFs/NT41802062016.pdf) | Audit Svc → SIEM pipeline, §3, plus incident-runbook (ops concern, not schema) |
| Consent management | DPDP Act 2023, §4/6/8 | [meity.gov.in DPDP Act text](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf) | `consent` table, §4.9 |
| Right to erasure | DPDP Act 2023, §12 | [dpdpa.com §8](https://www.dpdpa.com/dpdpa2023/chapter-2/section8.html) | Erasure workflow: soft-delete `identity` (tombstone traits), hard-delete after legal retention window, cascade credential/session/consent deletion |
| Breach notification (≤72h detailed report) | DPDP Act 2023 §8(6); DPDP Rules 2025 | [dpdpa.com §16](https://www.dpdpa.com/dpdpa2023/chapter-4/section16.html); [DPDP Rules 2025 PDF](https://www.dpdpa.com/DPDP_Rules_2025_English_only.pdf) | Incident-response runbook + Audit Svc timestamp trail as evidence source |
| Data localization (payment data) | RBI circular DPSS.CO.OD.No.2785/06.08.005/2017-18 | [rbi.org.in FAQ](https://www.rbi.org.in/commonman/english/scripts/FAQs.aspx?Id=2995) | All Postgres/Redis/Kafka/KMS deployed in India regions only (Mumbai/Hyderabad); no foreign-region replicas, ever |
| Cross-border transfer | DPDP Act 2023 §16 | [dpdpa.com §16](https://www.dpdpa.com/dpdpa2023/chapter-4/section16.html) | N/A by design (data never leaves India) — simplifies compliance vs relying on the Act's negative-list exception |

---

## 8. Observability (per blueprint §5)

- **Tracing:** OpenTelemetry SDK in every service, W3C Trace Context propagated through the API Gateway → all downstream calls including the synchronous KYC webhook; exported to Jaeger (self-hosted, India region — trace data may contain PII, so it's in-scope for data localization too).
- **Metrics:** Prometheus scrape per service; business metrics (login success/fail rate, MFA challenge latency, step-up trigger rate per risk level) alongside system metrics (DB pool saturation, Redis memory, Kafka consumer lag) — Grafana dashboards per tenant + aggregate.
- **Logging:** structured JSON; a PII-masking middleware runs before any log line leaves the process boundary (mask email/phone/account-number patterns) — required before forwarding to SIEM (Splunk/ELK), since logs are otherwise a DPDP-scope data leak vector.

---

## 9. Phased roadmap

1. **Phase 0 — Foundations:** `tenant`, `identity`, `credential` tables; Identity Service + Credential Service; Postgres RLS scaffolding; Redis session store skeleton.
2. **Phase 1 — Core auth:** password + OTP login/registration flows; e-KYC synchronous webhook hook; Session Service; Auth-Delegate Adapter v1 (login-provider contract against the in-house AS, using its real challenge/accept/reject API).
3. **Phase 2 — MFA & step-up:** TOTP, WebAuthn credential types; risk_signal + MFA/Risk Service v1 (rule-based, no ML); step-up flow trees per tenant.
4. **Phase 3 — Multi-tenancy & federation:** dedicated-schema tenant provisioning; SAML2 + OIDC Identity Brokering; claim dialects/mapping; per-tenant branding.
5. **Phase 4 — Compliance hardening:** hash-chained WORM audit log; consent management + DPDP erasure workflow; HSM/KMS integration for `secret_data` envelope encryption; PII log-masking middleware.
6. **Phase 5 — Scale-out:** Kafka event mesh to fraud/SIEM consumers; multi-region active-active (Mumbai + Hyderabad) with Patroni + regional Redis; full OpenTelemetry/Prometheus/Grafana rollout; load testing to 99.99% SLA target.

---

## 10. Consolidated references

**Ory Kratos** — https://www.ory.com/docs/kratos/self-service · identity schema: https://www.ory.com/docs/kratos/manage-identities/identity-schema · credentials: https://www.ory.com/docs/kratos/concepts/credentials · sessions: https://www.ory.com/docs/kratos/session-management/overview · hooks: https://www.ory.com/docs/kratos/hooks/configure-hooks · production guide: https://www.ory.com/docs/kratos/guides/production · source: https://github.com/ory/kratos

**Ory Hydra (auth-delegation pattern, §1.4/§3.6/§4.6)** — login/consent flow: https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow · "OAuth2 server without user management": https://github.com/ory/hydra · security architecture: https://www.ory.com/docs/hydra/security-architecture

**WSO2 Identity Server** — multitenancy: https://is.docs.wso2.com/en/6.1.0/references/concepts/introduction-to-multitenancy/ · claim dialects: https://is.docs.wso2.com/en/5.10.0/learn/configuring-claim-dialects/ · adaptive auth: https://is.docs.wso2.com/en/6.0.0/references/adaptive-authentication-js-api-reference/ · token persistence: https://is.docs.wso2.com/en/6.1.0/deploy/token-persistence/ · multi-region: https://wso2.com/library/articles/2018/04/multi-region-deployment-for-wso2-identity-server-part-1/

**Ping Identity** — authentication policies: https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_authentication_policies.html · PingOne Protect risk: https://docs.pingidentity.com/pingone/threat_protection_using_pingone_protect/p1_protect_risk_evaluations.html · MFA devices: https://docs.pingidentity.com/pingone/directory/p1_manage_a_users_devices.html · environments/populations: https://docs.pingidentity.com/pingone/directory/p1_groups_vs_populations.html · JWKS rotation: https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_jwks_endpoint.html · DaVinci Flow Conductor: https://docs.pingidentity.com/connectors/flow_conductor_connector.html

**Keycloak** — core concepts: https://www.keycloak.org/docs/latest/server_admin/index.html · credential model: https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/credential/hash/PasswordHashProvider.html · Argon2 default: https://www.keycloak.org/2024/06/keycloak-2500-released · flows: https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/authentication/flows.adoc · caching/HA: https://www.keycloak.org/server/caching

**Standards** — OAuth 2.0: RFC 6749 · OpenID Connect: https://openid.net/specs/openid-connect-core-1_0.html · WebAuthn: https://www.w3.org/TR/webauthn-3/

**RBI** — Digital Payment Security Controls MD: https://rbidocs.rbi.org.in/rdocs/notification/PDFs/MD7493544C24B5FC47D0AB12798C61CDB56F.PDF · IT Governance MD: https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12562 · Cyber Security Framework 2016: https://www.rbi.org.in/commonman/Upload/English/Notification/PDFs/NT41802062016.pdf · Data localization FAQ: https://www.rbi.org.in/commonman/english/scripts/FAQs.aspx?Id=2995

**DPDP** — Act 2023 text: https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf · §8 (consent/breach): https://www.dpdpa.com/dpdpa2023/chapter-2/section8.html · §16 (cross-border): https://www.dpdpa.com/dpdpa2023/chapter-4/section16.html · DPDP Rules 2025: https://www.dpdpa.com/DPDP_Rules_2025_English_only.pdf
