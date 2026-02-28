# Iperius Backup Security Advisories

This repository contains detailed documentation of two vulnerabilities identified in Iperius Backup, along with fully functional Proof-of-Concept tools for testing and demonstration purposes.

Both findings demonstrate critical cryptographic weaknesses in the application's encryption mechanisms — a hardcoded static encryption key for credential storage and a predictable key derivation for job file encryption — enabling offline credential recovery and local privilege escalation to `NT AUTHORITY\SYSTEM`.

---

## Iperius Backup Vulnerabilities and CVE References

- **CVE-2026-XXXXX** — `universal-credential-recovery.md`
  *Universal Credential Recovery via Static Encryption Key*

- **CVE-2026-XXXXX** — `privilege-escalation-job-injection.md`
  *Privilege Escalation via Encrypted Job File Injection*

---

## Advisory Files

- `advisories/universal-credential-recovery.md` — Complete technical analysis of the hardcoded credential encryption key, including reverse engineering methodology (Ghidra + WinDbg), KDF recovery, and Decryption Oracle technique
- `advisories/privilege-escalation-job-injection.md` — Complete technical analysis of the MachineGuid-based job file encryption bypass, including service internals reverse engineering and automated exploitation

---

## Proof-of-Concept Tools

- `poc/decrypt_iperius.py` — Standalone Python script for offline decryption of all Iperius Backup credentials
- `poc/iperius_job_inject.c` — C program that automates the full privilege escalation chain: key derivation, command encryption, and malicious `.ibj` file generation
- `poc/poc.md` — Usage instructions for both PoC tools

> :warning: **Warning:** Use the PoC tools only in a controlled test environment. Do **not** run on production systems.

---

## Affected Versions

- **Tested on:** Iperius Backup v8.7.2 (Windows)
- **Fixed in:** Iperius Backup v8.7.4 (partial — see advisories for details)

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-01-31 | Initial report submitted to Iperius via support ticket #214578 |
| 2026-02-07 | Vendor acknowledged and began engagement |
| 2026-02-14 | Detailed technical reports delivered |
| 2026-02-21 | Iperius v8.7.4 released with partial fixes (DPAPI for credentials, folder hardening option) |
| 2026-02-28 | Verification testing completed |
| TBD | CVE assignment |
| TBD | Public disclosure (90-day deadline from initial report) |

---

## Disclaimer

All tests were performed in a controlled environment. This repository is intended for research, educational purposes, and responsible disclosure only.

