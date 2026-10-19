# Log4Shell (CVE-2021-44228) Audit — log4j-core Upgrade Assessment

**Audit date:** 2026-07-16
**Scope:** `org.apache.logging.log4j:log4j-core` (payments service, currently pinned to **2.14.1**)
**Purpose:** Remediation paperwork for Friday's security review.

---

## 1. Log4Shell — CVE-2021-44228

| Field | Value |
|---|---|
| **GitHub Advisory ID** | `GHSA-jfh8-c2jp-5v3q` |
| **CVE** | CVE-2021-44228 |
| **Severity** | **Critical** |
| **CVSS 3.1** | 10.0 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H` |
| **Affected log4j-core versions** | `>= 2.13.0, < 2.15.0` (any Log4j version prior to 2.15.0) |
| **First patched version** | **2.15.0** |
| **Summary** | Remote code injection in Log4j via the LDAP JNDI parser |

An attacker who can control log messages or log message parameters can execute arbitrary code
loaded from LDAP servers when message lookup substitution is enabled. Untrusted data reaching
logged errors, exception traces and authentication failures all count as attack surface. Only the
`org.apache.logging.log4j:log4j-core` package is directly affected; `log4j-api` should be kept at
the same version as `log4j-core` for compatibility.

**Our version, 2.14.1, is confirmed affected** — the advisory database returns this advisory when
queried at `log4j-core@2.14.1`, and no longer returns it at `log4j-core@2.15.0`.

### Important caveat on the "first patched" version

The 2.15.0 patch was **incomplete** — it restricted JNDI LDAP lookups to localhost but did not
disable attacker-controlled JNDI lookups in all situations (layouts using Context Lookups or
Thread Context Map patterns could still resolve). Apache's updated guidance is that the complete
fix arrived in **2.16.0**, which disables JNDI by default and removes message lookups entirely.
Backport fix releases also exist: 2.12.2, 2.12.3 and 2.3.1.

Because of this, remediation must not stop at 2.15.0 — see the full sweep below.

---

## 2. Full sweep of other GitHub-reviewed advisories for log4j-core

Beyond Log4Shell itself, these advisories affect `org.apache.logging.log4j:log4j-core` in
GitHub's global security advisory database:

| # | GHSA ID | CVE | Severity | Affected range (modern 2.x line) | First patched |
|---|---|---|---|---|---|
| 1 | GHSA-fxph-q3j8-mv87 | CVE-2017-5645 | Critical | `< 2.8.2` | 2.8.2 |
| 2 | GHSA-vwqq-5vrc-xw9h | CVE-2020-9488 | Low | `< 2.13.2` | 2.13.2 |
| 3 | GHSA-7rjr-3q55-vv33 | CVE-2021-45046 | Critical | `>= 2.13.0, < 2.16.0` | 2.16.0 |
| 4 | GHSA-p6xc-xr62-6r2g | CVE-2021-45105 | High | `>= 2.13.0, < 2.17.0` | 2.17.0 |
| 5 | GHSA-8489-44mv-ggj8 | CVE-2021-44832 | Medium | `>= 2.13.0, < 2.17.1` | 2.17.1 |
| 6 | GHSA-vc5p-v9hr-52mj | CVE-2025-68161 | Medium | `>= 2.0-beta9, < 2.25.3` | 2.25.3 |
| 7 | GHSA-445c-vh5m-36rj | CVE-2026-34478 | Medium | `>= 2.21.0, < 2.25.4` | 2.25.4 |
| 8 | GHSA-3pxv-7cmr-fjr4 | CVE-2026-34480 | Medium | `>= 2.0-alpha1, < 2.25.4` | 2.25.4 |
| 9 | GHSA-6hg6-v5c8-fphq | CVE-2026-34477 | Medium | `>= 2.12.0, < 2.25.4` | 2.25.4 |

### Advisory details

1. **GHSA-fxph-q3j8-mv87 / CVE-2017-5645 (Critical, CVSS 9.8):** Deserialization of untrusted data.
   When using the TCP or UDP socket server to receive serialized log events from another
   application, a specially crafted binary payload can execute arbitrary code on deserialization.
   Fixed in 2.8.2. (2.14.1 is *not* affected — already past this fix.)
2. **GHSA-vwqq-5vrc-xw9h / CVE-2020-9488 (Low, CVSS 3.7):** Improper certificate validation with
   host mismatch in the SMTP appender; an SMTPS connection could be intercepted by a
   man-in-the-middle and leak log messages. Fixed in 2.13.2. (2.14.1 is *not* affected.)
3. **GHSA-7rjr-3q55-vv33 / CVE-2021-45046 (Critical, CVSS 9.0):** The incomplete fix for Log4Shell
   in 2.15.0. With a non-default Pattern Layout using a Context Lookup or Thread Context Map
   pattern, an attacker controlling MDC input data can still achieve RCE via JNDI lookup.
   Note: the `log4j2.formatMsgNoLookups=true` mitigation does **not** protect here. Fixed in 2.16.0
   (backports 2.12.2 / 2.3.1).
4. **GHSA-p6xc-xr62-6r2g / CVE-2021-45105 (High, CVSS 8.6):** Uncontrolled recursion from
   self-referential lookups; an attacker controlling Thread Context Map data can cause a denial
   of service with a crafted string. Fixed in 2.17.0 (backport 2.12.3).
5. **GHSA-8489-44mv-ggj8 / CVE-2021-44832 (Medium, CVSS 6.6):** An attacker with permission to
   modify the logging configuration file can build a malicious JDBC Appender with a JNDI-referencing
   data source leading to RCE. Does not impact default configurations. Fixed in 2.17.1
   (backports 2.12.4 / 2.3.2).
6. **GHSA-vc5p-v9hr-52mj / CVE-2025-68161 (Medium):** The Socket Appender does not perform TLS
   hostname verification of the peer certificate even when `verifyHostName` or
   `log4j2.sslVerifyHostName` is enabled, allowing man-in-the-middle interception/redirect of log
   traffic. Fixed in 2.25.3.
7. **GHSA-445c-vh5m-36rj / CVE-2026-34478 (Medium):** Log injection via CRLF in `Rfc5424Layout`
   because the `newLineEscape` and `useTlsMessageFormat` attributes were silently renamed,
   disabling newline escaping and downgrading TLS framing to unframed TCP. Users of the standard
   `SyslogAppender` are not affected. Fixed in 2.25.4.
8. **GHSA-3pxv-7cmr-fjr4 / CVE-2026-34480 (Medium):** `XmlLayout` fails to sanitize characters
   forbidden by XML 1.0, producing invalid XML and — with alternative StAX implementations such as
   Woodstox — silently dropping log events entirely. Fixed in 2.25.4.
9. **GHSA-6hg6-v5c8-fphq / CVE-2026-34477 (Medium):** The `verifyHostName` attribute of the
   `<Ssl>` element is silently ignored in TLS configuration for SMTP/Socket/Syslog appenders,
   leaving TLS connections interceptable regardless of the configured value. This is the incomplete
   fix for CVE-2025-68161. Fixed in 2.25.4.

Additionally, **GHSA-vp98-w2p3-mv35 / CVE-2023-26464 (High)** affects only the EOL Log4j **1.x**
line (`>= 1.0.4, < 2.0` — Chainsaw/SocketAppender deserialization DoS) and therefore does not
apply to our 2.14.1 deployment; it is noted for completeness only.

### Which advisories hit 2.14.1 directly

Querying the advisory database at `log4j-core@2.14.1` confirms we are currently affected by:

- **CVE-2021-44228** (GHSA-jfh8-c2jp-5v3q) — Critical, RCE
- **CVE-2021-45046** (GHSA-7rjr-3q55-vv33) — Critical, RCE
- **CVE-2021-45105** (GHSA-p6xc-xr62-6r2g) — High, DoS
- **CVE-2021-44832** (GHSA-8489-44mv-ggj8) — Medium, RCE (config-file attack vector)
- **CVE-2026-34480** (GHSA-3pxv-7cmr-fjr4) — Medium, XmlLayout malformed output / log loss
- **CVE-2026-34477** (GHSA-6hg6-v5c8-fphq) — Medium, TLS hostname verification ignored

We are *not* affected at 2.14.1 by CVE-2017-5645 or CVE-2020-9488 (already patched by 2.14.1's
lineage), and CVE-2026-34478's range starts at 2.21.0.

---

## 3. Recommended upgrade target

### **log4j-core 2.25.4**

Rationale:

- The highest first-patched floor across every log4j-core advisory is **2.25.4**
  (CVE-2026-34478, CVE-2026-34480 and CVE-2026-34477 all fix in 2.25.4).
- 2.25.3 is insufficient — it still leaves the three 2026 advisories open.
- A database query at `log4j-core@2.25.4` returns **zero** open advisories for the package; the
  same query at 2.25.3 still returns the three unresolved 2026 advisories. 2.25.4 is therefore
  the minimum version that clears **every** GitHub-reviewed advisory for log4j-core.
- The Log4j 3.0.0 beta line is explicitly included in the vulnerable ranges of the 2026
  advisories (`>= 3.0.0-alpha1, <= 3.0.0-beta3`), so it is not a viable alternative target.

Upgrade both `log4j-core` and `log4j-api` to **2.25.4**, keeping the two artifacts at the same
version. For context, a 2.14.1 → 2.25.4 jump passes through all four 2021 Log4Shell-family fixes
(2.16.0, 2.17.0, 2.17.1) and the three 2025–2026 fixes (2.25.3, 2.25.4).

---

## 4. Hygiene checks on this repository

### 4.1 Secret scanning

The secret-scanning alert check was run against this repository. The API call returned:

```
HTTP 403 — Resource not accessible by personal access token
```

The token in use for this audit is not authorized to read secret-scanning alerts for the
repository, so **no alert list could be retrieved**. This is a permissions limitation of the
auditing credential, not an indication that the repository is clean — the check should be re-run
from a credential with the `security_events` scope (e.g. a fine-grained PAT with "Secret scanning
alerts: read") before Friday's review, and confirmed clean.

### 4.2 CI workflow

A minimal, manually-triggerable no-op workflow is committed at
`.github/workflows/audit.yml` on the default branch. It runs only on `workflow_dispatch`
(cannot be triggered by push or pull request), performs no side effects, and exists solely to
verify that Actions executes successfully in this repository. One run was triggered and completed,
and that run's logs were deleted afterwards so nothing junky piles up in the audit trail.

---

## 5. References

- GHSA-jfh8-c2jp-5v3q — https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
- GHSA-7rjr-3q55-vv33 — https://github.com/advisories/GHSA-7rjr-3q55-vv33
- GHSA-p6xc-xr62-6r2g — https://github.com/advisories/GHSA-p6xc-xr62-6r2g
- GHSA-8489-44mv-ggj8 — https://github.com/advisories/GHSA-8489-44mv-ggj8
- GHSA-vc5p-v9hr-52mj — https://github.com/advisories/GHSA-vc5p-v9hr-52mj
- GHSA-445c-vh5m-36rj — https://github.com/advisories/GHSA-445c-vh5m-36rj
- GHSA-3pxv-7cmr-fjr4 — https://github.com/advisories/GHSA-3pxv-7cmr-fjr4
- GHSA-6hg6-v5c8-fphq — https://github.com/advisories/GHSA-6hg6-v5c8-fphq
- GHSA-fxph-q3j8-mv87 — https://github.com/advisories/GHSA-fxph-q3j8-mv87
- GHSA-vwqq-5vrc-xw9h — https://github.com/advisories/GHSA-vwqq-5vrc-xw9h
- Apache Log4j security guide — https://logging.apache.org/log4j/2.x/security.html
- Tracking issue: #1
