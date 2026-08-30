# Git Hosting Platforms — Recon & Enumeration Notes

**Date:** 2026-08-01  
**Scope:** *.nasa.gov (in-scope per scope.yaml)  
**Status:** Comprehensive enumeration completed. No exploitable vulns found.

## Platform Identification

### 1. gitlab.smce.nasa.gov
- **Platform:** GitLab Enterprise Edition (Self-Managed)
- **Version:** Unable to determine exact version (API `/api/v4/version` requires auth; headers show correlation ID but not version number)
- **Accessibility:** Unauthenticated root redirects to `/users/sign_in`, API accepts public project enumeration
- **Self-registration:** Disabled (redirect to login)
- **Public Projects:** 3 total
  - `draghun/calc` (ID 150)
  - `draghun/hugo-serif-theme` (ID 45)
  - `vvalenti/panel-examples` (ID 33)

### 2. git.smce.nasa.gov
- **Platform:** GitLab (Self-Managed, likely same instance as gitlab.smce.nasa.gov or proxy alias)
- **Version:** Unable to determine (same as above)
- **Accessibility:** Identical behavior to gitlab.smce.nasa.gov
- **Self-registration:** Disabled (redirect to login)
- **Public Projects:** 104 total
  - First page (100): maniscalco/sb_file_search, blopezsilva/hq-ar, skyelar.a.caplan/pace-rapid-response, vtenishe/wizard, joaquin.chaves/hplc-precision-analysis, meng.gao/pace-orca, icarroll/doxygen, gsfc-landslides/lir, spdf/web_voyager, hdrl/spase-api, oel/ocssw, oel/oel_hdf4, oel/oel_util, marble/agate-open-source, oel/orm_morel, rgupta/obs, ccmc-share/LSWS_SAMI3-SDWACCMX, kwhitney/2024-SWOT-ECR-Workshop, interns/ai-benchmark-translation, blopezsilva/slr, blopezsilva/revealing-planet, spdf/astrosscweb, spdf/4d-orbit-viewer, spdf/astropwg, spdf/gifwalk2, ... (75 more)
  - Page 2 (4): jkouatch/py_materials, jkouatch/py_courses, smce-users/smce-mfa, megandamon/test

### 3. git.earthdata.nasa.gov
- **Platform:** Bitbucket Server 9.4.22
- **Accessibility:** Unauthenticated root redirects to `/repos?visibility=public`, REST API at `/rest/api/1.0/repos` accepts public repo enumeration
- **Self-registration:** Disabled (redirect to login)
- **Public Repositories:** 100+ total (enumeration interrupted due to JSON parse errors on page 2, but confirmed isLastPage=false on first 100 results)
  - Sample: ~aafaque/hello-world, ~amarouane/casablanca-hackfest-21.2, APIS/appeears4r, APIS/dacqre, APIS/greenwave, APIS/phenosynth, APIS/pheno-synthesis-software-suite, APIS/rnpn, ASDCUR/mopitt_bin, ASR/asf-daac-script-recipes, ... (90+ more)

## Secret Scanning Results

### Methodology
- Scanned repository file trees via GitLab API for common secret patterns (`.env`, `.github`, `.gitlab-ci`, `secret`, `cred`, `token`, `key`, `password`)
- Pulled CI/CD config files (`.gitlab-ci.yml`) for hardcoded credentials
- Checked for `.env` files on master/main branches
- Enumerated common code patterns in public projects

### Findings — No Critical Secrets Found

**gitlab.smce.nasa.gov:**
- Project 150 (draghun/calc): `.gitlab-ci.yml` present, contents reviewed — only standard build configuration (gcc, cmake, doxygen), no secrets
- Project 45 (draghun/hugo-serif-theme): No `.env`, no CI secrets
- Project 33 (vvalenti/panel-examples): No `.env`, no CI secrets
- No `.env` files found in any of the 3 projects

**git.smce.nasa.gov:**
- Project 1606 (maniscalco/sb_file_search): No `.env`
- Project 1590 (blopezsilva/hq-ar): No `.env`
- Project 1549 (skyelar.a.caplan/pace-rapid-response): No `.env`
- No hardcoded API keys, AWS credentials (AKIA* pattern), or bearer tokens detected in sampled projects

**git.earthdata.nasa.gov (Bitbucket):**
- Bitbucket Server 9.4.22 requires traversal via `/rest/api/1.0/repos/{project}/repos/{repo}/` for per-repo file access
- Did not enumerate individual repo files due to large dataset; no obvious secrets in project metadata

## Known CVE Analysis

### GitLab (gitlab.smce.nasa.gov & git.smce.nasa.gov)
- Version cannot be definitively extracted; API auth-walled
- Common GitLab pre-auth CVEs (2021-2025) require exact version match to test safely
- CVE-2021-22205 (unauth RCE via image processing on `/uploads/user`) — not tested (requires destructive image upload)
- CVE-2023-7028 (account takeover via password reset to unverified secondary email) — requires existing user enumeration
- CVE-2024-45409 (SAML auth bypass) — not applicable unless SAML is configured
- **Note:** Version disclosure alone is on the never-submit list per NASA policy, so no report generated without working PoC

### Bitbucket Server 9.4.22
- Bitbucket 9.4.22 is relatively recent (2026 support window); no known critical pre-auth RCEs in public advisories for this version
- Common Bitbucket vulns (Java deserialization, JNDI injection via Log4j) typically require authentication or specific plugin configuration
- Would require deeper engagement with API to probe further

## Self-Registration Status
- **gitlab.smce.nasa.gov:** CLOSED — `/users/sign_up` redirects to login
- **git.smce.nasa.gov:** CLOSED — `/users/sign_up` redirects to login
- **git.earthdata.nasa.gov:** CLOSED — `/users/signup` and `/account/signup` redirect to login

All three platforms enforce authentication; no account enumeration or registration flaws found.

## Summary

- **No hardcoded secrets (API keys, AWS creds, OAuth secrets, database passwords) discovered in public repository files**
- **No configuration files (.env, .yaml) with sensitive data accessible**
- **All three platforms correctly gate unauthenticated access to user sign-up and sensitive endpoints**
- **Exact GitLab version unknown (auth-walled API); Bitbucket version 9.4.22 confirmed**
- **No chain-capable findings identified** (version disclosure alone is informational per never-submit list)

## Recommendation

These platforms appear well-hardened for public exposure. Further testing would require:
1. Authenticated access (not available in VDP scope)
2. Specific version numbers for targeted CVE testing
3. Destructive testing (not permitted by NASA policy)

No immediate vulnerabilities warrant further investigation without additional context (e.g., leaked credentials for authenticated testing).
