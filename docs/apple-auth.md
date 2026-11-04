# Apple authorization and native session handoff

Migration `0040_apple_auth` adds APPLE identities, encrypted revocation credentials,
and expiring login challenges. Existing user IDs, providers, workspaces, receipts,
and applied migrations remain unchanged. Run `npm run prisma:migrate:prod` then
`npm run prisma:generate` during deployment before starting the new backend.

## Configuration

| Server setting | Value |
| --- | --- |
| `APPLE_TEAM_ID` | Ten-character Team ID from Apple Developer |
| `APPLE_KEY_ID` | Ten-character ID of the Sign in with Apple key |
| `APPLE_PRIVATE_KEY` | Full `.p8` PEM, real newlines or literal `\n`, in a secret manager |
| `APPLE_IOS_CLIENT_ID` | `com.odixtec.inchange`, matching the App ID and Xcode bundle ID |
| `APPLE_WEB_CLIENT_ID` | Services ID associated with the primary iOS App ID |
| `APPLE_REDIRECT_URI` | `https://inchange.odixtec.com/auth/apple-return` |
| `APPLE_TOKEN_ENCRYPTION_KEY` | Dedicated base64-encoded 32 random bytes |
| `MOBILE_AUTH_ENABLED` | `true` after the website's mobile sign-in page is deployed |
| `APP_URL` | `https://inchange.odixtec.com` |

The frontend release guide covers App ID, Services ID, keys, private email relay,
Xcode signing and store metadata. Do not put Apple private keys in Vite variables.
Client secrets are ES256 JWTs minted on demand for five minutes. Apple identity
tokens are validated against Apple's RS256 JWKS, exact issuer/audience, expiration,
subject and challenge nonce. Remote calls time out after ten seconds.

`GET /api/v1/auth/providers` exposes availability, never keys. Apple remains
unavailable with incomplete/invalid configuration. Production cookies must remain
Secure and HttpOnly for access/refresh; the readable expiry hint is not a credential.
The native app calls the existing website `/api/v1` proxy over native HTTP, avoiding
cross-site cookie changes. Keep `COOKIE_DOMAIN` empty (host-only) or set to the
canonical website domain/parent. Do not set it to the API-only host. Retain existing
CORS restrictions; adding `*` or disabling cookie security is unnecessary.

## Protocol

1. `/auth/challenge` (login) or authenticated `/auth/connect/challenge` stores the
   SHA-256 of a client verifier, a nonce, intended provider/client, optional referral
   attribution, expiry and optional connecting user ID. Proofs are never stored raw.
2. Apple web uses Apple's JS popup; iOS uses ASAuthorizationAppleIDProvider. The
   authorization code and retained proof go to `/auth/apple`, which claims the
   challenge once before exchanging the code. A failed/uncertain attempt requires
   a fresh consent flow; no automatic replay of a spent provider code occurs.
3. Apple `sub` is authoritative. Names are optional display data, used only on new
   signup. Repeat consent can omit name/email. Verified private relay email works.
   A matching existing email requires signing into that account and explicitly
   connecting Apple; the service never silently merges accounts based on email.
4. Google/OC native login opens `/auth/mobile` in ASWebAuthenticationSession using
   the existing web clients. The browser initialization proof is in the URL
   fragment, cleared after consumption, and separate from the app-held redemption
   verifier. The one-time return code expires after 60 seconds. Callback interception
   alone cannot redeem it; duplicate/concurrent redemption yields one session.
5. Access/refresh cookies are issued only to the native redemption request.
   Sign-in/linking state is bound on the server rather than inferred from the
   external browser's possibly unrelated login. No access/refresh token is in a
   return URL or localStorage. Abandoned challenge records expire in ten minutes
   and are purged when new challenges are created; account purge also removes them.

## Revocation, deletion and operations

Apple refresh tokens use AES-256-GCM with random IVs and identity/client-bound
associated data. Separate credentials are retained for web and iOS authorization.
Credentials are not included in profile/user projections. Keep the encryption key
backed up in the secret manager: changing it without re-encrypting stored tokens
prevents revocation. Key rotation requires decrypt/re-encrypt with the old/new keys
before discarding the old one. Apple signing-key rotation does not change this key.

After the existing deletion grace period and blocker checks, the deletion worker
revokes each Apple grant before deleting credentials or scrubbing the account.
Apple sign-in/session creation and deletion serialize on the user row so a new
credential cannot be added after the deletion worker snapshots it. Failed revocation
keeps the account and credentials intact, records a FAILED deletion with an actionable
reason, and appears in the existing platform attention queue. After fixing connectivity
or key configuration, retry that request through the platform deletion action.
No plaintext token or Apple error body is logged. Revocation can be safely repeated
if a subsequent database operation failed.

The Apple key must remain configured for revoking existing accounts even if new
Apple signups are later disabled. Test Hide My Email delivery and revocation using
real disposable Apple accounts before release. If transferring to a different Apple
Developer team, complete Apple's subject/relay migration process; do not replace
provider IDs or merge users by email.

## Validation

Automated tests use locally generated signing keys and mocked Apple endpoints,
plus isolated PostgreSQL databases. They cover signature/claims, first and repeated
consent, explicit linking, duplicate requests, encrypted token binding, web/iOS grant
retention, deletion failure/retry, and native handoff proofs. They do not validate
Apple portal registrations, real key permissions, Xcode signing or TestFlight.

On 2026-11-04 the complete backend suite passed: 1,222 tests across 74 files,
including 17 Apple/native authentication cases and two isolated migration cases.
TypeScript, production build, Prisma validation, scoped Apple/housing/receipt
formatting and staged/unstaged whitespace checks passed. No migration was applied
to the development or production database during verification.

References: [Apple token validation](https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens),
[token revocation](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens),
[account deletion](https://developer.apple.com/support/offering-account-deletion-in-your-app/).
