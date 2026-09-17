# Security Remediation Plan

This document outlines security findings from a review of the Simple OIDC Provider and a prioritized plan to address them.

## Summary of Findings

| ID | Severity | Area | Issue |
|----|----------|------|-------|
| S1 | Critical | Local directory | Plaintext password comparison and storage |
| S2 | High | Defaults / config | Hardcoded client_secret and cookie signing keys in source |
| S3 | High | Defaults | Default users.json ships with well-known plaintext passwords |
| S4 | Medium | Logging | Request headers (may contain Authorization/cookies) logged at info level |
| S5 | Medium | CSP | Content-Security-Policy allows `unsafe-inline` for scripts and styles |
| S6 | Low | Timing | Local directory lacks constant-time password compare (mitigated partially by MIN_AUTH_RESPONSE_TIME) |
| S7 | Low | Dependencies / ops | No automated dependency or container vulnerability scanning in CI visible from review |

SQLite and remote directory paths already use bcrypt correctly and reject plaintext stored passwords. The critical gap is the default `local` directory path used for quick-start / demo.

---

## S1 – Local directory plaintext passwords (Critical)

**Location:** `src/provider/src/directories/local-directory.ts`

```ts
const user = this.users.find(user => user.email === email && user.password === password);
```

**Impact:** Anyone with access to `users.json` (or env `DIRECTORY_USERS`) obtains usable credentials. Comparison is also timing-sensitive.

**Plan:**
1. Import `bcrypt` (already a dependency).
2. In `validate()`:
   - Prefer `bcrypt.compare` when the stored value starts with `$2`.
   - For non-bcrypt values in development only: optionally allow comparison then re-hash and log a deprecation warning; in production reject plaintext (mirror `SqliteDirectory`).
3. Document that production local directories must ship bcrypt hashes only.
4. Add unit tests for hash accept / plaintext reject paths.

**Suggested acceptance criteria:**
- Local directory never accepts plaintext passwords when `NODE_ENV=production`.
- Existing bcrypt hashes continue to work.
- Timing mitigation (existing `MIN_AUTH_RESPONSE_TIME`) remains.

---

## S2 – Hardcoded secrets in configuration (High)

**Location:** `src/provider/src/configuration.ts` defaults

- Fixed `client_id` / `client_secret`
- Fixed `cookies.keys` value

**Impact:** Default deployments that do not override env vars share known secrets. Cookie key reuse allows session forgery across instances that use the defaults.

**Plan:**
1. Remove static production-usable secrets from defaults.
2. On startup in production:
   - Require `CLIENT_SECRET` (or `CLIENTS` / `CONFIG`) and `COOKIES_KEYS` (already partially validated).
   - Fail fast with clear error if missing (extend `validateEnvironment` / `validateProductionConfig`).
3. In non-production, generate ephemeral secrets with `crypto.randomBytes` (already partially done for cookies) and log a clear warning that they are not suitable for production.
4. Update README and security guide: never rely on defaults outside local demos.

---

## S3 – Default users.json plaintext credentials (High)

**Location:** `docker/provider/users.json`

Well-known credentials (`admin@localhost` / `Rays-93-Accident`, etc.) are documented publicly and stored in plaintext.

**Plan:**
1. Ship demo users with bcrypt hashes (use cost factor ≥ 10).
2. Keep plaintext only in docs examples that are clearly marked “dev only, hash before use”.
3. Prefer documenting SQLite / remote directory for any non-demo use so passwords are hashed by default.
4. Consider a first-run warning when default demo credentials are still active.

---

## S4 – Sensitive request logging (Medium)

**Location:** `src/provider/src/index.ts`

```ts
provider.use(async (ctx, next) => {
  console.log(`[PROVIDER] ${ctx.method} ${ctx.path} - Headers:`, ctx.headers);
  await next();
});
```

**Impact:** Authorization headers, cookies, and other secrets can land in logs.

**Plan:**
1. Log method, path, status, and a redacted header set only (e.g. omit `authorization`, `cookie`, `set-cookie`).
2. Gate verbose header dumps behind `LOG_LEVEL=debug` or an explicit `DEBUG_HEADERS=true`.
3. Align with the audit-logging recommendations already in `docs/guides/security.md`.

---

## S5 – CSP `unsafe-inline` (Medium)

**Location:** security headers middleware in `index.ts`

**Impact:** Weakens XSS mitigations for interaction and management UIs.

**Plan:**
1. Move inline scripts/styles out of Pug templates where practical, or introduce nonces.
2. Tighten CSP step-wise: first drop `unsafe-inline` for scripts, then styles.
3. Regression-test login, consent, and management UI pages.

---

## S6 – Timing / comparison hygiene (Low)

Local directory string equality is not constant-time. Partial mitigation exists via minimum response delay.

**Plan:** After bcrypt adoption (S1), rely on `bcrypt.compare` (constant-time for the crypto part) and keep the floor delay for non-crypto paths (missing user, validation errors).

---

## S7 – Supply-chain / CI hygiene (Low)

**Plan:**
1. Add `npm audit` (and optionally `npm audit --omit=dev`) to the existing build-and-test workflow.
2. Add container image scanning (e.g. Trivy) on the published image.
3. Pin or regularly refresh base image (`node:*-alpine`) and document the cadence.

---

## Recommended implementation order

1. **S1 + S3** – Stop plaintext auth on the default path and hash demo users.
2. **S2** – Force secret overrides in production; remove static secrets from defaults.
3. **S4** – Redact logging immediately (small change, high value).
4. **S5** – CSP tightening (UI-impacting, needs careful testing).
5. **S7** – CI/audit automation.

## Out of scope / already adequate

- SQLite directory already rejects plaintext and uses bcrypt.
- Security headers (frame options, nosniff, HSTS in production) are present.
- Input length limits and email validation on login exist.
- Non-root Docker user and multi-stage build are in place.
- Prototype pollution guard in `mergeDeep` is present.

## Testing checklist for the remediation PR series

- [ ] Local directory: bcrypt hash login succeeds; plaintext rejected in production.
- [ ] SQLite path unchanged (existing tests still pass).
- [ ] Production start without `COOKIES_KEYS` / client secret fails with clear message.
- [ ] Dev start still works with generated ephemeral keys.
- [ ] Login/consent UI renders under tightened CSP (or with nonces).
- [ ] Logs no longer contain Authorization or Cookie headers by default.
- [ ] `npm audit` clean or documented exceptions for the release.

## Disclosure note

Default credentials and the existence of plaintext local-directory storage are already public in the README and docs. Treat this plan as hardening for deployments that copy the demo configuration into non-demo environments, not as a zero-day.
