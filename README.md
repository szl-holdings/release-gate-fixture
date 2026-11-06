<!-- szl:header v1 -->
<!-- Native identity: szl-brand@4309f6fce89179331b0b3ed8c99494e76c5be256; Orbit v2 icon. -->
<p>
  <a href="https://github.com/szl-holdings">
    <img src="https://raw.githubusercontent.com/szl-holdings/szl-brand/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/logos/orbit-v2/suite/szl-icon-32.svg" alt="SZL Holdings — Orbit v2" width="32" height="32" />
  </a>
</p>

**Control before action. Evidence after.**

[Product](https://a-11-oy.com) · [Proof](https://a11oy.net) · [GitHub organization](https://github.com/szl-holdings)
<!-- /szl:header -->

# Release Gate Fixture

An offline, fail-closed fixture for checking whether release metadata agrees with a caller's trusted policy and exact candidate pins.

**A passing metadata result always returns `release_authorized: false`.** This repository does not approve, merge, publish or deploy a release.

## Start here

The evaluator uses Python 3 and its standard library. Run the three test modules from the repository root:

```bash
python -m unittest -v test_release_gate review_tests test_repo_contract
```

The checked-in examples contain synthetic identities, repeated-character revisions and digests, and reserved `.invalid` evidence URLs. Reproduce their metadata-consistent case with the explicit fixture clock:

```bash
python release_gate.py \
  --manifest example-manifest.json \
  --policy example-policy.json \
  --expected-head 1111111111111111111111111111111111111111 \
  --expected-digest sha256:2222222222222222222222222222222222222222222222222222222222222222 \
  --candidate-author author@example.invalid \
  --now 2026-10-10T09:30:00Z
```

Expected output:

```json
{"diagnostics": [], "metadata_gate": "passed", "release_authorized": false}
```

The clock override makes this historical fixture reproducible. Without it, the evaluator uses the current UTC clock, so the example observations become stale under the example policy's one-hour maximum age.

## What is checked

The caller supplies the trusted policy, candidate revision, artifact digest, candidate author and optional test clock. The local manifest is untrusted input.

| Contract | Check |
| --- | --- |
| Candidate binding | Every applicable record must match the exact trusted revision and digest; the candidate author must also match. |
| Required checks | The set must match the trusted policy exactly, and every reported status must be `passed`. |
| Review metadata | The reviewer must be allowlisted and differ from the candidate author. |
| Rights metadata | Rights must be explicitly allowed and the license identifier must be allowlisted. |
| Rollback metadata | A current, candidate-bound rollback record is required. |
| Time | Observations require a known timezone and must fit the policy's age and future-skew bounds. |
| Input shape | Unknown or missing fields, wrong JSON types, duplicate keys, non-finite constants and files over 1,048,576 bytes are rejected. |
| Evidence URI | Only a conservative HTTPS URI shape is accepted; the evaluator does not resolve or fetch the URI. |

## Read the source

| File | Purpose |
| --- | --- |
| [release_gate.py](./release_gate.py) | Validation functions, bounded JSON loading and the command-line entry point. |
| [example-policy.json](./example-policy.json) | Synthetic policy for the reproducible fixture. |
| [example-manifest.json](./example-manifest.json) | Synthetic metadata aligned with that policy and the example candidate pins. |
| [test_release_gate.py](./test_release_gate.py) | Evaluator, parsing, boundary and CLI regression tests. |
| [review_tests.py](./review_tests.py) | Additional adversarial input, clock, size and read-only behavior regressions. |
| [test_repo_contract.py](./test_repo_contract.py) | Repository contract checks: the installed module set, this README's example, exit codes and size limit, and that CI, the *Start here* command and pytest each run every test module. |

The CLI writes a JSON result to standard output. Exit code `0` means metadata consistency passed, `1` means a validation rule blocked it, and `2` means the input files or clock could not be loaded or parsed. Argument-parser usage errors also exit with code `2`.

## Evidence boundary

The fixture validates supplied metadata. It does not verify a signature, fetch an evidence report, authenticate a reviewer, establish license rights, prove an artifact was built or tested, or exercise a rollback. Its independent-review rule is a metadata comparison, not proof that an independent person performed a review.

No result grants release authority. A real release controller would need its own trusted evidence retrieval, authentication, artifact verification and authorization path. This repository provides no provider publisher or deployed application.

<sub>The native Orbit v2 artwork is from [SZL Holdings / szl-brand](https://github.com/szl-holdings/szl-brand/tree/4309f6fce89179331b0b3ed8c99494e76c5be256), reused with its [CC BY 4.0 attribution and trademark notices](https://github.com/szl-holdings/szl-brand/blob/4309f6fce89179331b0b3ed8c99494e76c5be256/NOTICE). This attribution does not assign a new license to the fixture's source code.</sub>

Estate on Hugging Face: models, datasets and Spaces are published under the [SZLHOLDINGS](https://huggingface.co/SZLHOLDINGS) org.
