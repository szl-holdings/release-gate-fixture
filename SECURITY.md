# Security Policy

## Trust Tier

**Trust Tier 1** — SZL Holdings is committed to coordinated, responsible disclosure for all SZL Holdings repositories.

## Reporting a Vulnerability

Please report security vulnerabilities by e-mail to: **security@szlholdings.com**

Please include:

- A clear description of the issue and its potential impact.
- Steps to reproduce, including any proof-of-concept code, requests, or payloads.
- The affected version, commit SHA, or environment.
- Your name and contact details for follow-up and credit (optional).

## Disclosure Process

We commit to:
- Acknowledging your report within **72 hours**
- Providing an initial assessment within **7 days**
- Disclosing the resolution within **90 days** of report (industry-standard coordinated-disclosure window)

We ask that you give us a reasonable opportunity to investigate and patch before public disclosure. We do not pursue legal action against good-faith security research.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` | ✅ |

This repository has no tags or GitHub releases yet; `pyproject.toml` declares the unreleased version 0.1.0. Add a row here when a release is tagged.

## Scope

This repository contains one standard-library Python module (`release_gate.py`), its test modules, synthetic example files and GitHub Actions workflows. It builds no container image and publishes no package.

In scope:

- Any input that makes `release_gate.py` report `"metadata_gate": "passed"` for metadata the README's *What is checked* table says must be blocked, or return anything other than `"release_authorized": false`.
- Input handling in `release_gate.py` (size limit, duplicate keys, non-finite numbers, timestamps), including crashes or resource exhaustion from a crafted manifest or policy file.
- The workflows in `.github/workflows/`, for example token permissions or handling of untrusted input.

Out of scope:

- Checks the README's evidence boundary says the fixture does not perform: signature verification, evidence retrieval, reviewer authentication, license-rights verification, proof that an artifact was built or tested, and rollback exercise. Their absence is documented, not a vulnerability.
- The synthetic identities, digests and reserved `.invalid` URLs in `example-manifest.json` and `example-policy.json`.
- Third-party dependencies, including the GitHub Actions the workflows use (please report upstream).
- Social engineering, physical attacks, or denial-of-service against shared infrastructure.

## Org policy

Canonical org policy: https://github.com/szl-holdings/.github/blob/main/SECURITY.md
This file applies that policy to `szl-holdings/release-gate-fixture`, with the supported versions and scope narrowed to what this repository contains.

## Hall of Thanks

Researchers who responsibly disclose vulnerabilities will be acknowledged here.
