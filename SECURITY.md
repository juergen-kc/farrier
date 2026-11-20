# Security policy

Farrier ships a component that runs as root (`farrier-helper`), so we take security reports
seriously and treat helper issues as the highest priority.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
the **Security** tab → **Report a vulnerability**.

Please include:
- the affected version and macOS version
- the steps to reproduce, or a proof of concept
- the impact (for example "local user can delete arbitrary root-owned file via helper")

We aim to acknowledge reports within 3 working days and to agree on a disclosure timeline
with you. We credit reporters unless you prefer otherwise.

## In scope

- Privilege escalation through `farrier-helper` or its XPC interface
- Bypassing on-device approval for T3 or T4 plans
- Getting Farrier to delete, move, or change something outside what a plan shows, including
  symlink and race conditions
- Rule-pack loading flaws that let a user pack exceed its restrictions
- Prompt-injection paths that lead to an action **without** the documented approval
- Signature or notarization issues in release artifacts

## Out of scope

- Attacks that require root, or an already compromised signed Farrier binary
- A user who knowingly approves a harmful plan
- How your AI client or model provider handles data (see
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#privacy-what-leaves-the-machine))

## Supported versions

Before 1.0, only the latest release receives security fixes.

## Verifying releases

Release artifacts are Developer ID signed, notarized, and published with GitHub build
provenance attestations:

```bash
gh attestation verify Farrier-<version>.zip --repo <owner>/farrier
```

```bash
codesign --verify --deep --strict --verbose=2 /Applications/Farrier.app
```

```bash
spctl --assess --type execute --verbose /Applications/Farrier.app
```
