# Enterprise Identity Provider (IdP) Architecture Blueprint
## Target Audience: AI Coding Assistant / Engineering Team
**Domain:** Top Indian Bank
**Objective:** Blueprint for building a secure, scalable, and compliant Enterprise Identity Provider (IdP).

---

## 1. Authentication Functionalities
The platform must support modular, decoupled authentication flows to cater to Retail, Corporate, and Internal (Employee) users.
*   **Core Flows:** Login (Passwordless/Biometric first, fallback to Password), Registration (with e-KYC/Aadhar integration hooks), Secure Logout (Global logout via OIDC Front-Channel/Back-Channel).
*   **Session Management:** Stateful/Stateless hybrid. Redis-backed centralized session store for immediate invalidation. Configurable absolute and idle timeouts per tenant/user type.
*   **MFA & Step-Up Auth:** 
    *   Support for SMS OTP (via telecom gateways), Email OTP, TOTP (Google/Microsoft Authenticator), and FIDO2/WebAuthn (Biometrics/Hardware Keys).
    *   **Contextual/Step-Up:** Triggered based on risk signals (e.g., new device, geo-velocity, high-value transaction).
*   **Account Recovery:** Self-service flows protected by MFA, ID verification, and rate-limiting to prevent enumeration.

## 2. Multi-tenancy
The architecture must be a Multi-tenant SaaS-like model, isolating different business units (e.g., Retail Banking, Wealth Management, Corporate Banking, Internal IAM).
*   **Isolation Strategy:** Logical separation at the database level using `tenant_id` for configuration/users, with optional dedicated schemas for high-compliance corporate tenants.
*   **Per-Tenant Configuration:**
    *   Custom branding (UI themes, logos, email templates).
    *   Custom password policies, session lengths, and MFA enforcement rules.
    *   Custom Identity Providers (e.g., allowing Corporate tenants to federate their own Azure AD).

## 3. Security
Security is paramount for an Indian financial institution.
*   **Cross-Tenant Access:** Strict logically-enforced boundaries (RBAC/ABAC at the API Gateway and Service layer) ensuring Tenant A cannot access Tenant B's users or configs.
*   **Data Encryption:**
    *   **At Rest:** AES-256 for PII data. Cryptographic keys managed via a Hardware Security Module (HSM) or Cloud KMS.
    *   **In Transit:** TLS 1.3 only, strict cipher suites.
*   **Credential Security:** Passwords hashed using Argon2id or PBKDF2 with unique salts.
*   **Token Security:** Asymmetric signing for JWTs (RS256/ES256), short-lived access tokens, and securely stored, rotatable refresh tokens.

## 4. Compliance (Indian Banking Context)
Must adhere to strict regulatory frameworks dictated by the Reserve Bank of India (RBI) and government acts.
*   **Regulations:** RBI Master Directions on Digital Payment Security Controls, RBI guidelines on Information Security.
*   **Acts:** Digital Personal Data Protection (DPDP) Act 2023 (consent management, right to be forgotten, data localization).
*   **Data Localization:** All user data, logs, and cryptographic keys must reside in data centers physically located within India.
*   **Audits:** Immutable, tamper-evident audit trails for all authentication and administrative actions (integrating with SIEM/WORM storage).

## 5. Monitoring & Observability
Deep visibility into the platform's health and security posture.
*   **Tracing:** Distributed tracing using OpenTelemetry, pushing to tools like Jaeger or AWS X-Ray to track request paths across microservices.
*   **Metrics:** Prometheus + Grafana for business metrics (login success/fail rates, MFA latency) and system metrics (CPU, Memory, DB pool limits).
*   **Logging:** Structured JSON logging. PII must be masked before leaving the application boundary. Forwarded to centralized SIEM (e.g., Splunk, ELK).

## 6. Ecosystem & Infrastructure Topology
Designed for high availability (99.99%) and massive scale.
*   **Topology:** Multi-AZ, Active-Active across at least two geographical regions in India (e.g., Mumbai and Hyderabad) with automated failover.
*   **Infrastructure:** Kubernetes (EKS/AKS or on-prem OpenShift) for microservices orchestration.
*   **Data Stores:**
    *   **Relational DB (Configurations & User Profiles):** PostgreSQL (highly available cluster).
    *   **Caching & Sessions:** Redis Cluster.
    *   **Event Streaming:** Apache Kafka for publishing async events (e.g., `user.registered`, `login.failed`) to downstream systems like fraud engines.

## 7. Customization & Standards
Built on open standards to ensure interoperability with the bank's legacy and future ecosystem.
*   **Protocols:** 
    *   OIDC (OpenID Connect) and OAuth 2.0 for modern web and mobile apps.
    *   SAML 2.0 for legacy enterprise applications.
*   **Extensibility Hooks:** 
    *   Webhooks/Event-driven triggers to call the bank's proprietary services (e.g., calling a legacy Core Banking System to validate an account number before registration, or calling an internal SMS gateway for OTP).
*   **API-First:** Completely headless API design allowing the bank to build native, custom frontend UIs that interact with the IdP securely.
