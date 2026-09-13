# Kratos + Hydra Session & OAuth Compliance Architecture — Discussion Summary

Companion to the [Enterprise OAuth 2.0/2.1 Rewire Plan](../README.md). Where Phase 1 (`01`–`03`) scoped the OAuth authorization-layer engine choice, this document captures a follow-on working session on **integrating Ory Kratos (identity) with the existing Ory Hydra (OAuth2/OIDC) deployment** — session/token architecture, browser vs. native app handling, OAuth2 compliance review of an existing homegrown auth service, step-up authentication, and multi-persona SSO.

Session date: 2026-09-12 to 2026-09-13.

---

## Table of Contents

1. [Context](#1-context)
2. [Problems Discussed, Context & Recommendations](#2-problems-discussed-context--recommendations)
   1. [Browser vs. native app session strategy with Hydra + Kratos](#21-browser-vs-native-app-session-strategy-with-hydra--kratos)
   2. [Industry-sensitivity vs. architecture: does "bank" mean "always PKCE-in-browser"?](#22-industry-sensitivity-vs-architecture-does-bank-mean-always-pkce-in-browser)
   3. [Proposed BFF + opaque-token + session-bridge design](#23-proposed-bff--opaque-token--session-bridge-design)
   4. [Is the existing Hydra-centric enterprise architecture archaic?](#24-is-the-existing-hydra-centric-enterprise-architecture-archaic)
   5. [Kratos multi-persona architecture: schemas, native gaps, LDAP bridge, instance separation](#25-kratos-multi-persona-architecture-schemas-native-gaps-ldap-bridge-instance-separation)
   6. [Session/token TTL policy: 30-minute absolute, 5–15-minute idle](#26-sessiontoken-ttl-policy-30-minute-absolute-515-minute-idle)
   7. [Compliance review: the head architect's programmatic Java auth service](#27-compliance-review-the-head-architects-programmatic-java-auth-service)
   8. [Does RFC 9126 (PAR) change the verdict?](#28-does-rfc-9126-par-change-the-verdict)
   9. [Bookmarkable login pages vs. stale login_challenge](#29-bookmarkable-login-pages-vs-stale-login_challenge)
   10. [Validating and reinitiating a login_challenge](#210-validating-and-reinitiating-a-login_challenge)
   11. [UX friction of the system-browser redirect](#211-ux-friction-of-the-system-browser-redirect)
   12. [Step-up authentication (AAL2) with a session-bound token cache](#212-step-up-authentication-aal2-with-a-session-bound-token-cache)
   13. [Correction: no PII/claims stored in Hydra; version correction (OEL vs OSS)](#213-correction-no-piiclaims-stored-in-hydra-version-correction-oel-vs-oss)
   14. [Cross-persona SSO: was removing SSO from Hydra the right call?](#214-cross-persona-sso-was-removing-sso-from-hydra-the-right-call)
3. [Detailed Q&A Log](#3-detailed-qa-log)
4. [Open Items / Follow-ups](#4-open-items--follow-ups)

---

## 1. Context

The bank already runs Ory Hydra at enterprise scale as its OAuth2/OIDC backbone (every internal system that touches security uses Hydra-issued opaque tokens). The team is now introducing **Ory Kratos** for identity, while simultaneously reconciling this with:

- An existing, large-scale Hydra deployment on **v1.11.10**, being bridged to **v26.2.0** via a custom version-mapping service.
- A homegrown Java "auth service" that performs a programmatic OAuth dance and separately polls Kratos's `whoami`.
- Incoming **RBI** regulatory scrutiny.
- A **headless** platform model: the bank never renders end-user UI — all browser/native UI is built and owned by third-party integrators, except for the bank's own internal staff/corporate login screen.

All findings below were produced by dispatching topic-specific advisor agents (`ory-oss`, `ory-hydra-advisor`, `oauth-compliance-advisor`) that verified claims against Ory's live documentation, GitHub source/issues/discussions, and the relevant IETF RFCs/drafts rather than relying on training-data recall — consistent with this engagement's standing verification-rigor practice.

---

## 2. Problems Discussed, Context & Recommendations

### 2.1 Browser vs. native app session strategy with Hydra + Kratos

**Problem:** How should Hydra/Kratos responsibilities split between browser apps and native/mobile apps, without compromising OAuth standards?

**Context:** Kratos owns authentication only (its own session cookie/token); Hydra owns OAuth2/OIDC issuance and keeps a **separate** session cookie from Kratos. The login/consent bridge app between them is example code, not a hardened Ory OSS component.

**Recommendation:**
- Browser apps: Ory's own security-model doc explicitly recommends **against** using OAuth2 tokens for session management by default — use Kratos session cookies directly; bring in Hydra only when a genuine third-party/API-delegation need exists. When Hydra is needed, use public client + PKCE.
- Native apps: public client, no secret, PKCE, **system browser only** (never an embedded WebView), exact-match redirect URIs, strict refresh-token rotation (avoid the opt-in "graceful" rotation mode except as a last resort).
- Known gap: PKCE-enforced-by-default is contested by real GitHub issues/discussions on Hydra — verify against the exact pinned version, don't assume.
- Known tension: Hydra brands itself an "OAuth2.1 provider" but remains OpenID-certified for the Implicit profile — explicitly exclude `implicit` from `grant_types` rather than trusting the tagline.

### 2.2 Industry-sensitivity vs. architecture: does "bank" mean "always PKCE-in-browser"?

**Problem:** Initial assumption — "regulated industry ⇒ every browser app must be public-client + PKCE; cookie-based sessions are a lower-security, retail-grade compromise."

**Context/Verdict:** This is backwards. The IETF draft *OAuth 2.0 for Browser-Based Apps* ranks architectures in **decreasing order of security**: Backend-for-Frontend (BFF, tokens server-side, browser gets a cookie) is ranked highest and is **"strongly recommended for business applications, sensitive applications, and applications that handle personal data."** Public-client + PKCE with tokens held in browser JS is a lower tier on that same list. The deciding factor is architecture (does the browser need to hold and present a bearer token itself) and the XSS threat model — not industry vertical.

**Recommendation:** Don't default every browser app to public-client+PKCE. Ask first whether the browser app needs to independently present a bearer token to a separate resource server; if not, the BFF/cookie pattern is the more defensible choice, including for a bank.

### 2.3 Proposed BFF + opaque-token + session-bridge design

**Problem:** Team's own design — BFF as confidential client, PKCE-protected code exchange, browser gets only a Kratos session cookie, BFF caches `{Kratos session-id, Hydra opaque access token, cached identity info}` and revalidates against Kratos on every introspection/userinfo call for instant revocability, opaque tokens chosen over JWT deliberately.

**Verified findings:**
- OAuth 2.1 draft (rev -16) mandates PKCE for **every** authorization_code grant, confidential clients included — a stricter bar than RFC 9700, which only makes PKCE a **SHOULD** for confidential clients (MUST only for public clients). Document which target spec you're citing.
- Kratos sessions and Hydra tokens have **independent lifecycles by default** — no built-in bridge. Kratos's only native revocation hook fires on password change only, not general logout. Revoking a Hydra login session does **not** revoke its tokens — a separate consent-session revocation call is required.
- `/oauth2/introspect` has zero Kratos-awareness — the "re-check Kratos on every call" design is genuine custom logic that has to be built; it is not something Ory ships.
- **Critique:** if you're already doing a live Kratos check on every call, the opaque token's revoke-by-lookup property becomes redundant. The more idiomatic, cheaper pattern is **push, not pull** — call Hydra's login-session **and** consent-session revocation directly from the logout path; reserve a live Kratos re-check as defense-in-depth, not the primary mechanism.

### 2.4 Is the existing Hydra-centric enterprise architecture archaic?

**Problem:** Leadership question — team has had "huge success" making Hydra the universal security backbone (client-credential caching, identity-master attributes baked into opaque-token session data, refresh-token-based indefinite session extension, logout = revoke + delete cache). Now introducing Kratos. Is this thinking outdated, and what does it mean for RBI compliance?

**Verdict — mixed, with one live security exposure:**
- **Sound, keep as-is:** the token-centric model for third-party integrators. The BFF/cookie debate never applied to that surface — integrators are separate trust domains, which is structurally a token relationship regardless of what Kratos does internally.
- **Real flaw, and exactly Kratos's job to fix:** baking identity-master attributes into the token, refreshed only periodically/at token refresh, creates two sources of truth with a real propagation gap. Recommendation: make Kratos the live source of truth; keep only stable identifiers (subject, session ID, ACR) in the Hydra token; have resource servers do a Kratos-backed lookup for anything that changes.
- **Live security exposure, unrelated to Kratos:** the "v26.2.0" bridge target is not "26 majors of hardening" — Ory switched to calendar versioning (`YY.Q.B`) at v25.4.0; the real lineage from v1.11.10 is one genuine breaking major (v1→v2, ~Jan 2025). **CVE-2026-33504** (SQLi via forged pagination tokens, CVSS 7.2) was introduced in v25.4.0 and fixed in v26.2.0, and it hits exactly the admin API endpoints (`listOAuth2Clients`, consent-session listing) the team's 5-minute cache-invalidation loop depends on. Action items: confirm the bridge terminates/reissues tokens via the patched v26.2.0 binary (not proxying v1.11.10), diff the *effective* config on both sides (a translation bridge tends to normalize to the lowest common denominator unless every security flag is re-asserted), and run a live PKCE-bypass test through the bridge in staging.
- **RBI:** no numbered rule found that the current pattern violates — the applicable July 2026 Commercial Banks Cybersecurity/Tech/Resilience/Assurance Directions are principle-based (least-privilege as a continuous property, Paras 105/109), not numeric-SLA-based. A commonly-cited "15-minute idle timeout" from the 2021 Digital Payment Security Controls direction could not be confirmed from primary text this session — verify independently. No RBI text specifically governs OAuth AS-to-third-party-integrator token lifetime — a genuine regulatory gap, not something to route around with an invented citation. Recommendation: add an absolute session cap regardless of continuous refresh activity now, as a proactive control, rather than waiting to be asked.

### 2.5 Kratos multi-persona architecture: schemas, native gaps, LDAP bridge, instance separation

**Problem:** Plan — one Kratos OSS instance with multiple identity schemas per persona; separate services around Kratos for whatever it doesn't provide (lockout, activation/deactivation, password expiry/rotation, enterprise comms, TOTP, passkeys); a second identity source for staff via LDAP-via-Azure-AD-OIDC bridge; is this "identity master, not full IdP" framing correct, and can staff + retail share one instance?

**Verified — three of six assumed gaps are not actually gaps:**

| Capability | Native in Kratos OSS? |
|---|---|
| Account lockout / brute-force protection | **No** — confirmed absent (GitHub #3037, #654, #134); even Ory Network only offers this as managed rate-limiting |
| Password expiry / forced rotation | **No** — no config surface exists |
| Activation/deactivation | **Yes** — identity `state` field, `PATCH /admin/identities/{id}` |
| TOTP | **Yes** — `selfservice.methods.totp` |
| Passkeys (distinct from generic WebAuthn) | **Yes** — native since Kratos v1.2, refined in v1.3 |
| Outbound lifecycle communications | **Delivery mechanics yes** (courier + templating); provider/deliverability quality is on you |

**Recommendation:** Build separate services only for lockout and password expiry — the genuine gaps. Building anything for activation, TOTP, or passkeys would duplicate what Kratos already does.

**Multi-schema policy scoping:** Kratos supports multiple `identity.schemas` for different trait shapes, but **password/MFA/lockout policy is global to the instance, not schema-scoped** — schemas don't give you different policy per persona.

**LDAP-via-Azure-OIDC bridge:** confirmed sound and correctly avoids a licensing trap — generic OIDC federation (`selfservice.methods.oidc`) is Apache-2.0 OSS; SAML/B2B "Organizations"/SCIM are explicitly gated to Ory Enterprise License.

**Single vs. multiple instances — this is the load-bearing finding:** `selfservice.methods.*.enabled` flags (password, oidc, webauthn, totp, passkey) are **flat, instance-wide booleans with no schema/flow scoping.** If OIDC is enabled for the staff Azure bridge, a retail-schema identity can call the login API directly and attempt it — hiding a button in the UI is presentation-only, not a trust boundary. The only mitigation is a before/after-login webhook checking `identity.schema_id`, and it **fails open by default** unless `response.ignore: false` is explicitly set.

**Verdict:** Don't unify staff and retail into one instance. Not for generic isolation hygiene — because this specific boundary (internal staff via corporate Azure AD vs. public retail customers) would become bank-built custom code you must personally guarantee never regresses, rather than a structural guarantee the product provides.

### 2.6 Session/token TTL policy: 30-minute absolute, 5–15-minute idle

**Problem:** How to configure "Kratos access token TTL" (a category error — Kratos has no access token) and Hydra session/token TTLs to satisfy a 30-minute absolute / 5–15-minute idle policy, and how refresh-token-based extension interacts with it.

**Key finding:** Neither Hydra nor Kratos has a native idle-timeout concept, confirmed directly by an Ory maintainer (Hydra GitHub Discussion #2246): activity/session tracking is explicitly the caller's responsibility. Hydra's refresh-token rotation is a **sliding window** — every refresh resets the TTL; there is no config key capping total elapsed session time regardless of refresh count.

**Recommended values:**

| Layer | Key | Value |
|---|---|---|
| Hydra access token | `ttl.access_token` | 5 min |
| Hydra refresh token | `ttl.refresh_token` | 30 min, `rotation_grace_period: 0` |
| Hydra ID token | `ttl.id_token` | 5 min (carries `auth_time`) |
| Kratos session | `session.lifespan` | 30 min |
| Hydra SSO cookie | `remember_for` | ≤ 1800s — **do not leave this longer than the absolute cap**, or silent SSO replay resets the window without re-presenting credentials |

**Outside both products entirely:** inject `auth_time` at consent-accept; build a stateful last-seen-timestamp layer (extending the existing token-cache/introspection loop) that rejects `now - auth_time > 30min` (absolute) or `now - last_seen > 15min` (idle). This is the actual enforcement point — the TTL configs above only bound the blast radius.

### 2.7 Compliance review: the head architect's programmatic Java auth service

**Problem:** A Java "auth service" validates credentials via Kratos, then programmatically drives the OAuth dance (PKCE + authorization code flow, using an HTTP client with a cookie jar to carry Hydra/Kratos cookies across calls), and issues the resulting Hydra access token directly to mobile/browser clients — explicitly to avoid a visible redirect for mobile. Is this an OAuth2 compliance violation?

**Verdict: Yes, confirmed, and the cookie-jar clarification does not change it.**
- Mechanically, `login_challenge`/`consent_challenge` cannot be fabricated — they require a real hit (even a headless, server-to-server one) to Hydra's actual `/oauth2/auth`. Automating the *public* endpoints via a scripted cookie-jar client (rather than the admin API) makes PKCE and redirect_uri validation genuinely exercised rather than theatrical — a real mechanical improvement over the initial (mis-)description.
- **But this is orthogonal to the actual violation.** The defect is functionally equivalent to ROPC (RFC 9700 §2.4: "insecurely exposes the credentials of the resource owner to the client") regardless of transport — whether via `grant_type=password` or a scripted HTTP client POSTing to a login form, the credential-collection locus is identical: the app's own UI, relayed by the backend, not a real user-agent rendering Hydra/Kratos's own page.
- RFC 8252 §8.12 forbids embedded WebViews for exactly this reason (host app can capture credentials, auto-submit forms to bypass consent). A scripted backend client with a cookie jar is **assessed as strictly worse** than an embedded WebView — there is no user-agent execution context on the device at all: no URL bar, no origin visibility, no possibility of an origin-bound WebAuthn/passkey ceremony.
- Two things did not need to change: two maintainers confirmed on Hydra Discussion #2562 that skipping the redirect or omitting real consent "would break OpenID Connect certification" and is "extremely hacky" — there's no maintainer-sanctioned version of what was attempted.

**Separately, on Kratos's `browser` vs. `api` self-service flow types:** Kratos ships a native `api`-flow type (`/self-service/login/api`, returns a `session_token` header instead of a cookie) built specifically for headless/backend clients. Switching to it is a legitimate, low-risk win — it eliminates the cookie-jar complexity entirely. **But it only fixes the Kratos-side plumbing.** It has zero bearing on the Hydra-side compliance question — whether Kratos issues a cookie or a token doesn't change whether a genuine, user-mediated `login_challenge`/`consent_challenge` round-trip through Hydra's real `/oauth2/auth` occurs.

**Direct conclusion:** violation confirmed against RFC 9700 §2.4 and RFC 8252 §8.12. Cannot continue as-is. The fix is architectural, not a backend rewrite: the interactive step must move into a real system browser (`ASWebAuthenticationSession`/Custom Tabs) that the user controls and observes; everything downstream (PKCE, code exchange, the Kratos `api`-flow cleanup) can stay as designed.

### 2.8 Does RFC 9126 (PAR) change the verdict?

**Problem:** Would adopting RFC 9126 (Pushed Authorization Requests) instead of/alongside RFC 9700/8252 remove the need for a browser redirect, or solve the stale-login_challenge-via-bookmark issue?

**Verdict: No, on both counts, confirmed.**
- PAR only changes *how* authorization parameters are transmitted (back-channel POST returning a `request_uri`) — RFC 9126 §4 explicitly retains the front-channel browser redirect to `/authorize?request_uri=...`. Interactive login/consent rendering is untouched.
- RFC 9700/8252 are IETF Best Current Practice documents (BCP 240 / BCP 212) — not legally self-enforcing, but the de facto baseline auditors and certification profiles use. **FAPI 2.0** (the actual banking-grade OpenID Foundation profile) mandates PAR with "shall" language **and separately, additively**, still mandates the RFC 8252 system-browser pattern and PKCE. No profile anywhere treats PAR as a substitute for the redirect.
- A pushed `request_uri` is typically shorter-lived than a `login_challenge` (~60s per RFC 9126's own recommendation) — bookmarking gets worse, not better, under PAR.
- Practical note: Hydra doesn't implement PAR at all (an earlier, dated finding in this engagement) — this option isn't even available today regardless of the native-app question.

### 2.9 Bookmarkable login pages vs. stale login_challenge

**Problem:** How to let users bookmark a login page without breaking the protocol or hitting a stale login_challenge.

**Recommendation (no protocol violation involved):** separate "the URL a human is allowed to keep" from "the URL a machine mints once and burns."
- Bookmark target = the bank's own stable client entry point (e.g. `https://app.bank.com/login`), carrying **no OAuth state**. On every hit, it constructs a **brand-new** authorization request (fresh `state`, fresh PKCE verifier/challenge) and redirects to `/oauth2/auth`.
- Never expose the login app's challenge-bearing URL or the `redirect_uri` callback (single-use code) as something meant to be bookmarked.
- Deep-link intent (e.g. "land on /statements after login") should be carried in the app's **own** query param (`/login?next=...`), read back via the app's own `state`, not via anything Hydra issues.

### 2.10 Validating and reinitiating a login_challenge

**Problem:** Is there a way to check whether a login_challenge is still valid, and to reinitiate it if not?

**Verified:**
- `GET /admin/oauth2/auth/requests/login?login_challenge=...` validates a challenge, but **the status-code contract is unreliable in the current release line** — Hydra was fixed years ago to return `410 Gone` + `redirect_to` for an already-used challenge, but GitHub Issue #3755 shows this regressed to `200` in v2.2.0 and was closed "not planned" with no confirmation of a fix in v26.2.0. A separately reported expired-challenge case returns `401` with no `redirect_to`. **Do not hardcode branching logic on a specific status code without empirically testing against the exact pinned Hydra build.**
- **No refresh/reinitiate primitive exists.** The only correct recovery is redirecting the browser back to the public `/oauth2/auth` endpoint from scratch with the original parameters, minting an entirely new challenge.
- Default TTL: 1 hour, via `ttl.login_consent_request`.
- Practical (community-sourced, not first-party Ory) pattern: stash the original `/oauth2/auth` request URL as a hidden field at render time; on **any** non-success response from validate/accept/reject, redirect to the stashed URL rather than trying to interpret the specific error code.

### 2.11 UX friction of the system-browser redirect

**Problem:** Pushback — leaving the app for a system browser plus a biometric prompt is user-unfriendly and doesn't complete in ~1 second; is the Java auth service justifiable given this friction?

**Verdict: No — and the friction argument makes the backend approach worse, not more justifiable, once traced through.**
- WebAuthn/passkey ceremonies require a real browser engine to collect and sign the origin into `clientDataJSON` (WebAuthn L3 §5.8.1/§1) — a backend HTTP client has no origin to bind and cannot construct this at all, under any implementation. The biometric prompt **is the authentication ceremony**, not overhead imposed by the redirect requirement. A backend-driven flow forecloses passkeys entirely and falls back to password — the weaker, more phishable option.
- The spec-sanctioned friction reducer is OpenID Connect Core's `prompt=none` (§3.1.2.1): if a valid AS session exists, the AS returns success silently, no visible UI, no biometric re-prompt. RFC 8252 §4 ties this directly to SSO. Biometrics should only be re-invoked when a fresh assertion is actually required (session expired, step-up).
- RFC 8252 §8.12 treats phishing resistance, credential non-exposure, and SSO as non-negotiable security properties — friction is addressed via implementation technique (session reuse, browser warm-up), never as grounds to bypass the pattern.

### 2.12 Step-up authentication (AAL2) with a session-bound token cache

**Problem:** Given the session-id-bound-to-cached-Hydra-token design, can Kratos step-up (AAL2) still be used?

**Verified — yes, mechanically compatible, but real wiring is required:**
- Confirmed in Kratos source (`session/manager_http.go`): step-up upgrades the **same** session ID in place (no new ID minted) — the cache key survives.
- But the cached snapshot goes stale the instant Kratos upgrades the live session — it must be actively refreshed on step-up completion, not left to the periodic revalidation window.
- Getting elevated assurance into the actual Hydra access token requires a **full new OAuth round-trip** — there is no in-place token upgrade. Correct sequence: RP sends a fresh `/oauth2/auth` request with `acr_values=<required>&prompt=login` (the `prompt=login` is what forces Hydra past the SSO/remember cookie) → login app reads the requested ACR off the `login_challenge` → checks Kratos's live AAL via `whoami` → drives Kratos step-up if needed → accepts the login, optionally setting `acr` → Hydra mints a new token. **Hydra does not auto-forward `acr_values` to Kratos** (confirmed via ory/hydra#3637) — this wiring exists nowhere except in the login app.
- `privileged_session_max_age` is confirmed **Kratos-self-service-flow-only** — it does not generalize to arbitrary bank actions. To gate a sensitive transaction on step-up freshness, the resource server must independently pull `whoami` and compare `now` against `authentication_methods[].completed_at` itself. **This directly reframes the head architect's `whoami`-polling design from earlier in the session:** if its actual purpose is checking step-up freshness (not general revocation), it is the correct and only way to do this — worth clarifying with him which problem it was actually solving.
- Hydra treats `acr_values` as inert, unenforced data — resource servers must explicitly check the resulting `acr` claim themselves; nothing stops an RP from skipping it and reusing a stale low-assurance token.

### 2.13 Correction: no PII/claims stored in Hydra; version correction (OEL vs OSS)

**Correction 1 — the team does not store `acr`/claims on the Hydra token; identity/assurance data lives entirely in their own cache, to avoid PII bloat and refresh-time overhead.** Confirmed this doesn't break anything and is arguably cleaner: `acr_values` + `prompt=login` are still needed purely as a **signal** to force the login app to run and check Kratos live — nothing requires writing `acr` back onto the Hydra token. Post-step-up, only the team's own cache needs refreshing with the new Kratos `whoami` result.

**Correction 2 — a version citation was wrong and needed to be retracted.** A prior finding cited `v26.3.7` for a Kratos AAL2-enrollment-handling improvement. The bank's own GitHub screenshot showed the actual latest public OSS release is `v26.2.0`. Re-verified directly: `ory.com/docs/self-hosted/oel/...` is the **Ory Enterprise License** changelog stream, which publishes combined, product-line-wide version numbers (Network + Hydra + Kratos + Keto + Polis + Elements together) that do **not** correspond to individual OSS repo tags. Checked the actual `v26.2.0` tag source (`session/error.go`): only `ErrNoSessionFound` is defined; no `session_aal2_enrollment_required` handling exists in OSS v26.2.0. **Corrected guidance:** do not rely on that enrollment-aware behavior on the current self-hosted OSS deployment — either build explicit handling for the no-second-factor case, or evaluate OEL specifically for this feature.

### 2.14 Cross-persona SSO: was removing SSO from Hydra the right call?

**Problem:** The team removed SSO from Hydra entirely, concluding `remember`/`remember_for`/`skip`/`prompt=none` can't support persona-scoped SSO (e.g. SSO for staff but not for a separate corporate persona on the same Hydra instance).

**Verdict: the underlying observation is correct, but the fix was an overreaction.**
- Confirmed directly in Hydra source (`consent/strategy_default.go`): `skip=true` is decided purely from whether the SSO cookie resolves to a subject — there is **no client_id comparison** in that path. A remembered session from a staff login genuinely will produce `skip:true` for a different client on the same browser. The bleed is real.
- **But `skip` is advisory, not enforced** — Ory's own docs state the login app "should" skip the UI, not that it must accept. Hydra never calls accept itself. A login app can see `skip:true` and still reject it, force fresh authentication, and only then accept.
- The `login_challenge` payload already includes the full `client` object (`client_id` and all) alongside `skip` — exactly the data needed to add one check: does this subject's persona match what's expected for this client, and only then honor `skip`.
- No Ory guidance recommends separate Hydra instances for this specific problem (unlike the Kratos method-scoping finding in §2.5, which had no in-app fix available).

**Recommendation:** reinstate SSO for the staff persona with a client-aware check added to the login app (roughly a one-conditional fix), rather than absorbing the UX and infrastructure cost of no SSO anywhere.

---

## 3. Detailed Q&A Log

> Condensed to the substantive question and the core of the response actually given. Full citations are in §2 above; this section preserves the conversational arc and reasoning.

**Q: Create an `ory-oss` subagent to help with Ory OSS capabilities/limitations/best practices, sourced from the latest information.**
A: Created `~/.claude/agents/ory-oss.md` (user-level), scoped to whole-ecosystem Ory questions (Kratos, Hydra, Keto, Oathkeeper, Polis, Talos), with explicit routing to `ory-hydra-advisor`/`permify-advisor` for deep single-product work. Grounded in live research rather than recall — found and encoded a real discrepancy where Ory's own docs contradict each other on Polis's OSS-vs-Enterprise licensing status, and instructed the agent to treat "OpenID Certified"/"OAuth2.1 provider" taglines as leads to verify, not proof of RFC coverage.

**Q: What does Ory recommend for combining Hydra and Kratos, specifically browser vs. mobile/native apps, without compromising OAuth standards?**
A: See §2.1. Kratos owns authentication, Hydra owns OAuth2/OIDC; browser apps default to Kratos-session-only unless a genuine token need exists; native apps use public client + PKCE + system browser. Flagged the login/consent bridge as example code the team must harden themselves, and the Implicit-grant-vs-"OAuth2.1 provider" tagline tension.

**Q: If I work in a bank or healthcare, isn't every browser app going to need public-client + PKCE? Maybe Ory's cookie-based recommendation is for retail/fashion industries, not regulated ones.**
A: Checked against the IETF *OAuth 2.0 for Browser-Based Apps* draft — this framing is backwards. See §2.2: BFF/cookie-based architecture is explicitly ranked as the **most** secure pattern and recommended for sensitive/business applications; the deciding factor is architecture and XSS threat model, not industry vertical.

**Q: [Proposes] BFF holding the token, PKCE for the code exchange, session token from Kratos tied to a Hydra opaque token cached in a backend with live Kratos session-info revalidation on every introspection call, opaque over JWT for revocability.**
A: See §2.3. OAuth 2.1 draft does mandate PKCE for confidential clients too (RFC 9700 only recommends it for them). Kratos/Hydra lifecycles are confirmed independent with no built-in bridge — the re-check-Kratos-live design is real, necessary custom logic, but push-based revocation on logout is more idiomatic and cheaper than a per-request pull check.

**Q: [Leadership framing] Is our team's Hydra-centric thinking archaic? We're on v1.11.10 bridging to v26.2.0, cache client-credential tokens, bake identity-master attributes into opaque tokens, extend sessions via refresh tokens indefinitely, logout = revoke + delete cache. We're also headless — integrators own the UI. What should we do with Kratos, and what about RBI?**
A: See §2.4. Not archaic on the token-centric integrator model. Real flaw: identity-attribute caching on the token (fix: Kratos as live source of truth). Live, unrelated risk found: CVE-2026-33504 hits exactly the admin endpoints the cache-invalidation loop depends on, and the version-bridge naming is misleading (calendar versioning, only one real major-version boundary in the gap). RBI: principle-based, no numeric SLA found; add an absolute session cap proactively regardless.

**Q: Can I maintain one Kratos OSS instance with multiple schemas per persona, wire separate services for things Kratos doesn't provide (lockout, activation, password expiry, comms, TOTP, passkeys), and bridge staff via LDAP→Azure OIDC — combined into one instance or separate?**
A: See §2.5. Three of the six assumed gaps (activation, TOTP, passkeys) are already native — building around them would be redundant. Lockout and password expiry are genuine gaps. LDAP-via-Azure-OIDC is valid and correctly OSS (unlike SAML). Critical finding: method-enablement is instance-global, not schema-scoped, so combining personas risks leaking "Sign in with Azure AD" to retail flows via direct API calls regardless of UI hiding — recommended separate instances for this specific reason.

**Q: We want 30-minute absolute session expiry with 5–15-minute idle expiry. Should I configure the Kratos access token TTL and Hydra session TTL to these numbers? How does refresh-token extension interact? What values?**
A: See §2.6. Corrected the premise (Kratos has no access token). Confirmed neither product has native idle-tracking (an Ory maintainer said so directly) or an absolute-cap-regardless-of-refresh primitive. Gave concrete TTL values across all three layers and flagged that `remember_for` must also be capped or SSO replay defeats the absolute cap.

**Q: You didn't answer the unification question fully — can I unify the OIDC staff instance with the multi-schema retail instance?**
A: Answered definitively in the same turn, see §2.5's "Single vs. multiple instances" finding — confirmed method-scoping is instance-global via `config.schema.json`, confirmed the webhook mitigation fails open by default, and gave a direct "don't unify" verdict grounded in that specific gap rather than generic isolation preference.

**Q: The head architect built a Java auth service that performs the whole OAuth dance programmatically (issuing a Hydra token after Kratos validation) and also regularly calls `whoami`. Isn't this a flaw/violation for browser apps? Why call `whoami` when a token already exists?**
A: Initial read (admin-API-driven, no real redirect at all): non-compliant, ROPC-equivalent, worse than an embedded WebView. On `whoami`: not a documented revocation bridge; either dead weight or a half-built attempt at closing the Kratos/Hydra revocation gap — asked what the code actually does on a failed `whoami` check.

**Q: [Correction] The programmatic dance is done via a Java backend using a cookie jar to drive the actual PKCE + auth code flow over the real public endpoints, not the admin API.**
A: Re-verified: the mechanical correction is real (PKCE/redirect_uri are now genuinely exercised, not theatrical) but doesn't change the verdict — see §2.7. The defect is *where credentials are entered*, which is unchanged; a cookie-jar HTTP client is not a "user-agent" under RFC 8252 regardless of fidelity, and it's assessed as worse than a WebView since there's no on-device browser context for WebAuthn/passkeys at all. Separately verified Kratos's native `api`-flow type as a legitimate but orthogonal plumbing fix (cleans up the cookie jar, doesn't touch the Hydra-side violation).

**Q: You're being too verbose — give me a direct conclusion: violation or not, and can it continue if compliant?**
A: Direct verdict given: yes, violation, cannot continue as-is. The one deciding fact — do credentials ever reach a real user-agent rendering Hydra/Kratos's own page — is no, so it's non-compliant per RFC 9700 §2.4 / RFC 8252 §8.12. Compliant fix: move the interactive step into a system browser; everything else can stay.

**Q: So a mobile app can't operate within its own boundary for login — it must redirect to a system browser, and the callback is what makes it compliant?**
A: Confirmed yes, walked through the four concrete steps (system browser launch with PKCE challenge → real login/consent UI rendered by the browser → redirect to registered URI with code → app exchanges code+verifier). Only the credential-entry step has to leave the app.

**Q: What if I use RFC 9126 (PAR) instead of 9700/8252 — is 9700/8252 mandated, and does PAR solve the redirect requirement and the stale-challenge/bookmark issue?**
A: See §2.8. PAR only changes parameter transport, not the redirect requirement (confirmed in RFC 9126 §4 itself). 9700/8252 are BCPs, not law, but are the de facto compliance baseline — and FAPI 2.0, the actual banking-grade profile, mandates PAR **additively** to (not instead of) the browser-redirect/RFC 8252 requirements. PAR's `request_uri` is shorter-lived than a login_challenge, so it makes the bookmark problem worse, not better. Also noted: Hydra doesn't implement PAR at all.

**Q: Is there something we can do to let users bookmark the login page without compromising the protocol or hitting the stale-challenge mishap?**
A: See §2.9. Separate the stable, state-free client entry point (bookmark this) from the ephemeral, AS-minted challenge (never bookmark this); always mint a fresh authorization request on load; carry deep-link intent in your own params, not Hydra's.

**Q: Is there a way to validate and reinitiate the login_challenge?**
A: See §2.10. Validation is possible via the admin GET, but the status-code contract is unreliable in the current Hydra release line (a real, cited regression, closed "not planned"). No reinitiate-in-place primitive exists — only a full restart at `/oauth2/auth`. Gave a defensive stash-and-redirect pattern since Ory doesn't document one.

**Q: Isn't going to a system browser for OAuth user-unfriendly, given biometric prompts and sub-1-second expectations? Is the Java auth service enough in that case?**
A: See §2.11. Verified WebAuthn/passkey ceremonies require a real browser origin binding that a backend cannot construct under any implementation — the biometric prompt *is* the authentication, not overhead. The compliant friction-reducer is `prompt=none`/SSO session reuse, not abandoning the pattern. Verdict unchanged: no.

**Q: Given our session-bound-token-cache design, can I still use Kratos step-up (AAL2) auth?**
A: See §2.12. Yes, mechanically — same session ID survives step-up — but real wiring is required: cache must be actively refreshed on step-up, and elevating the actual Hydra token requires a full new authorization round-trip since Hydra doesn't auto-forward `acr_values` to Kratos. Flagged that `privileged_session_max_age` doesn't generalize beyond Kratos's own flows, which reframes the earlier `whoami`-polling design as potentially the correct (if previously undocumented) way to check step-up freshness for the bank's own sensitive actions.

**Q: [Correction] We don't store `acr` or claims in Hydra during login/consent accept — we keep user info in our own cache to avoid PII bloat. Also, v26.3.7 doesn't exist — GitHub shows v26.2.0 as latest.**
A: See §2.13. Confirmed both corrections. Not storing `acr` on Hydra doesn't break anything — `acr_values`/`prompt=login` are still needed purely as a trigger signal. Retracted the v26.3.7 citation on the record: it was from the Ory Enterprise License changelog stream (product-line-wide version numbers, not 1:1 with OSS tags), and direct inspection of the real `v26.2.0` tag source confirmed the AAL2-enrollment handling referenced does not exist in the OSS line the bank actually runs.

**Q: We removed SSO from Hydra entirely because remember/remember_for/skip/prompt=none can't do persona-scoped SSO (e.g. staff-only SSO vs. corporate). Was that right?**
A: See §2.14. The underlying observation is correct — confirmed in Hydra's source that `skip` is subject+cookie-scoped, not client-scoped, so cross-persona bleed is real. But `skip` is advisory, not enforced, and the `login_challenge` payload already carries the `client_id` needed to build a one-conditional persona check in the login app. Verdict: removing SSO entirely was an overreaction to a fixable login-app gap, not a genuine Hydra structural limitation.

---

## 4. Open Items / Follow-ups

- [ ] Empirically test the Hydra v1.11.10→v26.2.0 bridge: confirm admin-API calls (the 5-minute cache-invalidation loop) actually hit the patched v26.2.0 binary given CVE-2026-33504; diff effective config on both sides; run a live PKCE-bypass test through the bridge in staging.
- [ ] Independently verify the RBI Digital Payment Security Controls "15-minute idle timeout" clause text directly from the primary PDF — could not be confirmed from primary source this session.
- [ ] Confirm with the head architect whether the `whoami`-polling design is intended as a revocation bridge (redundant, replace with push-based revocation) or a step-up-freshness check (legitimate, keep and formalize) — the answer changes the recommendation.
- [ ] Decide: build custom account-lockout and password-expiry services (confirmed genuine Kratos OSS gaps), or evaluate Ory Enterprise License for these plus the AAL2-enrollment-handling gap found in §2.13.
- [ ] Re-verify current Kratos version's actual behavior for the no-second-factor-enrolled AAL2 step-up case (confirmed absent in v26.2.0 OSS) and decide on interim handling in the login app.
- [ ] Design and code-review the persona-aware `client_id` check in the login app before reinstating SSO (§2.14).
- [ ] Migrate the Java auth service off the programmatic/cookie-jar pattern to a system-browser-based (AppAuth/ASWebAuthenticationSession) native flow, or a real front-channel redirect for browser apps — flagged as a compliance violation, not optional.
- [ ] If adopting Kratos's `api`-flow type for the backend-to-Kratos leg, confirm the `/api` endpoints are never also reachable from real end-user browsers elsewhere in the estate (Ory's own docs warn this is the actual misuse case for that flow type).
