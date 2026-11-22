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
   | `HOMEBREW_TAP_TOKEN` | optional: a fine-grained token with Contents read/write on the tap repository only (see Homebrew below) |

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
     rendered by `scripts/render-cask.sh` with the version and the zip's SHA-256),
   - commits `farrier.rb` to the Homebrew tap (if `HOMEBREW_TAP_TOKEN` is set).
4. Set `FarrierVersion.string` to the next `-dev` version.

## Homebrew

Farrier is installed from its own tap, `juergen-kc/homebrew-farrier`:

```bash
brew install --cask juergen-kc/farrier/farrier
```

The release workflow commits each release's rendered `farrier.rb` to the tap's `Casks/` folder. That needs one more
**environment secret**, `HOMEBREW_TAP_TOKEN`: a fine-grained personal access token limited to the tap repository,
with *Contents: read and write* and nothing else. Without it the workflow only warns, and `farrier.rb` (attached to the
GitHub release) is copied to the tap by hand. A different tap can be set with the repository variable
`HOMEBREW_TAP_REPO` (`owner/name`).

The tap runs `brew style` and `brew audit` on every change (its own CI).
