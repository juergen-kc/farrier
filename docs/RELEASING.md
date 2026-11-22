# Releasing Farrier

Releases are built, signed with **Developer ID**, **notarized** and published by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) when a version tag is pushed. Pull requests that
change the pipeline (and a manual run with "dry run" ticked) run the same build and checks ad hoc signed, without
notarizing or publishing.

## One-time setup

You need a paid Apple Developer Program membership; the **Account Holder** creates the certificate.

1. **Developer ID Application certificate.** developer.apple.com → Certificates → "+" → *Developer ID Application*
   (G2 Sub-CA). Create the CSR in Keychain Access, download the certificate, double-click it. Then export it with its
   private key from Keychain Access (My Certificates → the certificate → Export → `.p12`, with a strong password).
2. **App Store Connect API key for notarization.** appstoreconnect.apple.com → Users and Access → Integrations →
   Team Keys → "+", role *Developer*. Download the `.p8` (only once), note the **Key ID** and the **Issuer ID**.
3. **A GitHub environment named `release`** (repository Settings → Environments): add yourself as a required
   reviewer and restrict deployments to tags matching `v*`. Then add these **environment secrets**:

   | Secret | Value |
   |---|---|
   | `DEVELOPER_ID_CERT_P12` | `base64 -i DeveloperID.p12` |
   | `DEVELOPER_ID_CERT_PASSWORD` | the `.p12` export password |
   | `NOTARY_API_KEY_P8` | `base64 -i AuthKey_XXXXXXXXXX.p8` |
   | `NOTARY_API_KEY_ID` | the key ID |
   | `NOTARY_API_ISSUER_ID` | the issuer ID |

   Keeping them in the environment (not repository secrets) means only an approved release job can read them.

## Making a release

1. Set `FarrierVersion.string` in `Sources/FarrierCore/Version.swift` to `X.Y.Z` (no `-dev`) and merge it. The
   helper's version handshake uses this string, so the tag must match it; the workflow checks.
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Approve the `release` environment when GitHub asks. The workflow then:
   - runs the tests,
   - imports the certificate into a temporary keychain (deleted at the end),
   - builds `Farrier.app` with `scripts/build-app.sh` (hardened runtime, secure timestamp),
   - notarizes it with `notarytool` (waits up to 30 minutes) and staples the ticket,
   - checks that Gatekeeper says `source=Notarized Developer ID`,
   - publishes the GitHub release with `Farrier-X.Y.Z.zip`, `SHA256SUMS` and `farrier.rb` (the Homebrew cask,
     rendered by `scripts/render-cask.sh` with the version and the zip's SHA-256).
4. Set `FarrierVersion.string` to the next `-dev` version.

## Homebrew

The rendered `farrier.rb` goes into a tap repository (for example `juergen-kc/homebrew-farrier`, under `Casks/`).
Then: `brew install --cask juergen-kc/farrier/farrier`. Automating the tap update is a later step.
