# Google Workspace Security Investigation Tool (SIT) Policy Reference

## Overview
This document contains the formalized, sanitized configuration reference for active automated activity rules within our Google Workspace tenant. These rules are managed via the Security Investigation Tool (GSC rule type) to enforce automated threat detection, account isolation, data loss prevention (DLP), and administrative auditing.

---

## 📧 Gmail Event Rules

### 1. Link Domain Delete Emails
* **Policy Name:** `policies/[POLICY_ID_1]`
* **Status:** `ACTIVE`
* **Target Scope:** Organizational Unit `[ORG_UNIT_A]`
* **Trigger:** Incoming emails (`RECEIVED`) containing specific link domains.
* **Logic:** Case-insensitive string match if the payload contains any of the following:
  * `[MALICIOUS_DOMAIN_1]`
  * `[MALICIOUS_DOMAIN_2]`
  * `[MALICIOUS_DOMAIN_3]`
* **Automated Actions:**
  * **Soft Delete** email from recipient inboxes.
  * **Mark as Phishing** globally for tenant telemetry.
  * **Alert Dispatched:** Medium-severity email notifications routed to `[SOC_EMAIL_1]` and `[SOC_EMAIL_2]`.

### 2. Erate Email Search
* **Policy Name:** `policies/[POLICY_ID_2]`
* **Status:** `ACTIVE`
* **Target Scope:** Organizational Unit `[ORG_UNIT_A]`
* **Trigger:** Incoming emails (`RECEIVED`).
* **Logic:** Case-insensitive subject line contains the string `NDA/RFP`.
* **Automated Actions:**
  * **Send to Quarantine** for administrative review.
  * **Alert Dispatched:** Logged silently (Notification status explicitly set to `Disabled`).

---

## 👤 User Event Rules (Authentication & Identity Protection)

### 3. Google Admin Console Alert
* **Policy Name:** `policies/[POLICY_ID_3]`
* **Status:** `ACTIVE`
* **Target Scope:** Organizational Unit `[ORG_UNIT_A]`
* **Trigger:** User activity event.
* **Logic:** A user successfully executes a sensitive action (`RISKY_SENSITIVE_ACTION_ALLOWED`) containing the string `"admin"` **AND** the actor's source IP address does **NOT** originate from the trusted network block `[INTERNAL_IP_RANGE]`.
* **Automated Actions:**
  * **Alert Dispatched:** Medium-severity email notification routed to `[SOC_EMAIL_1]`.

### 4. Suspend Users Adding Filters to Gmail
* **Policy Name:** `policies/[POLICY_ID_4]`
* **Status:** `ACTIVE`
* **Target Scope:** Organizational Unit `[ORG_UNIT_A]`
* **Trigger:** User activity event.
* **Logic:** Mitigation rule targeting compromised accounts setting up persistence. Fires when an account flagged with a suspicious login event attempts a sensitive action (`RISKY_SENSITIVE_ACTION_ALLOWED`) containing the string `"filter"`.
* **Automated Actions:**
  * **Suspend User** immediately to prevent active data exfiltration or credential hijacking.
  * **Reset Password** automated enforcement.
  * **Alert Dispatched:** High-severity email notifications routed to `[SOC_EMAIL_1]` and `[SOC_EMAIL_2]`.

### 5. Google Admin (Restricted Identity Rule)
* **Policy Name:** `policies/[POLICY_ID_5]`
* **Status:** `ACTIVE`
* **Target Scope:** Organizational Unit `[ORG_UNIT_A]`
* **Trigger:** User activity event.
* **Logic:** Safeguard rule targeting restricted identity blocks. Fires when an identity explicitly belonging to the managed subdomain `[STUDENT_SUBDOMAIN]` successfully attempts a sensitive action (`RISKY_SENSITIVE_ACTION_ALLOWED`) on `admin.google.com`.
* **Automated Actions:**
  * **Suspend User** account termination.
  * **Alert Dispatched:** High-severity escalation to `[SOC_EMAIL_1]` with Super Admin priority flags.

### 6. Suspicious Login Thresholds
* **Policy Name:** `policies/[POLICY_ID_6]`
* **Status:** `ACTIVE`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Aggregated user security events.
* **Logic:** Time-series aggregation rule checking for a `SUSPICIOUS_LOGIN` valuation scoring **greater than 2** instances within an `86400s` (24-hour) rolling window.
* **Automated Actions:**
  * **Alert Dispatched:** Medium-severity notification routed to `[SOC_EMAIL_1]`.

### 7. Suspicious Login (Single Event Response)
* **Policy Name:** `policies/[POLICY_ID_7]`
* **Status:** `ACTIVE`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Real-time user login events.
* **Logic:** Fires immediately upon a standard successful login (`LOGIN_SUCCESS`) if the contextual evaluation model marks the flag `USER_LOGIN_IS_SUSPICIOUS = true`.
* **Automated Actions:**
  * **Alert Dispatched:** Generates an immediate security alert incident notification.

### 8. Suspicious Failed Password (Brute-Force Lockout)
* **Policy Name:** `policies/[POLICY_ID_8]`
* **Status:** `ACTIVE`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Real-time user login events.
* **Logic:** Prevents massive brute-forcing or automated credential stuffing. Fires when a login fails (`LOGIN_FAILURE`) and the endpoint context evaluates as highly anomalous or suspicious.
* **Automated Actions:**
  * **Suspend User** preemptive lock out to safeguard user integrity.
  * **Alert Dispatched:** Immediate threat alert routed to `[SOC_EMAIL_1]`.

---

## 🛠️ Admin Event Rules (Internal Audit & Controls)

### 9. Unauthorized User Deletion Tracking
* **Policy Name:** `policies/[POLICY_ID_9]`
* **Status:** `ACTIVE`
* **Target Scope:** Organizational Unit `[ORG_UNIT_A]`
* **Trigger:** Administrative API/Console events.
* **Logic:** Fires when an admin event captures code `18` (internal execution for structural user deletion).
* **Automated Actions:**
  * **Alert Dispatched:** Medium-severity tracking logged; active external email configurations are currently marked as `Disabled`.

### 10. Sensitive Global Admin Modifications
* **Policy Name:** `policies/[POLICY_ID_10]`
* **Status:** `ACTIVE`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Administrative API/Console events.
* **Logic:** Monitored baseline adjustment tracker checking for structural workspace changes inside a `3600s` (1-hour) window:
  * Toggling a core Google core application service status on/off.
  * Adjusting global multi-factor parameters (`ENFORCE_STRONG_AUTHENTICATION`).
  * Granting secondary administrative rights (`GRANT_ADMIN_PRIVILEGE`).
* **Automated Actions:**
  * **Alert Dispatched:** Dispatches an immediate evaluation alert directly to `[SOC_EMAIL_1]`.

---

## 💾 Google Drive Event Rules (Data Loss Prevention)

### 11. Global Drive Sharing Investigations
* **Policy Name:** `policies/[POLICY_ID_11]`
* **Status:** `ACTIVE`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Asset sharing mutations.
* **Logic:** Evaluates all access changes across the storage landscape (`CHANGE_USER_ACCESS`) on a rolling 24-hour time series window.
* **Automated Actions:**
  * **Alert Dispatched:** Email auditing notice sent to standard SOC logs.

### 12. Public Document Views Audit
* **Policy Name:** `policies/[POLICY_ID_12]`
* **Status:** `ACTIVE`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Asset interaction vectors.
* **Logic:** Triggers whenever an object whose default asset visibility structure is shared out to the web (`PUBLIC`) records an inbound read event (`VIEW`).
* **Automated Actions:**
  * **Alert Dispatched:** Low-severity documentation alert logged.

### 13. Drive Public Sharing Mitigation (Staging / Dry Run)
* **Policy Name:** `policies/[POLICY_ID_13]`
* **Status:** `DRY_RUN`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Real-time asset modifications.
* **Logic:** Pipeline test rule listening for accounts changing internal documentation parameters directly over to a `PUBLIC` global configuration matrix.
* **Automated Actions:**
  * **Log Matrix Execution Only:** No active threat intercept actions or notifications occur while marked in `DRY_RUN` posture.

---

## 🌐 Context-Aware Access (CAA) Rules

### 14. Outside US Login Denials
* **Policy Name:** `policies/[POLICY_ID_14]`
* **Status:** `ACTIVE`
* **Target Scope:** Tenant Root (`/`)
* **Trigger:** Perimeter network interaction logging.
* **Logic:** Fires off an event response whenever a geo-fenced boundary access condition triggers a structural block request (`ACCESS_DENY_EVENT`) targeting source origins outside authorized borders (e.g., non-US geoblocking constraints).
* **Automated Actions:**
  * **Alert Dispatched:** Email logging alert sent for edge monitoring.
