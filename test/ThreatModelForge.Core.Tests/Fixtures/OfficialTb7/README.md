# Official Microsoft TB7 semantic fixtures

These fixtures are derived from the three templates in
[`microsoft/threat-modeling-templates`](https://github.com/microsoft/threat-modeling-templates)
at commit `0ece9c71b6f3710b10d497bd1ef63e57805e7c3e`.

The upstream repository and these derived fixtures are licensed under the MIT License. See the
[pinned upstream source and license](https://github.com/microsoft/threat-modeling-templates/tree/0ece9c71b6f3710b10d497bd1ef63e57805e7c3e)
and the repository's [third-party attribution](../../../../NOTICE).

## Derivation

Each fixture retains the complete template semantic graph: manifest, threat metadata, generic and
standard element types, hierarchy, attributes, categories, threat types, and raw generation-filter
text. To avoid checking in large embedded image payloads, every non-empty `<Image>` body is replaced
with `sha256:<digest>`, where `digest` is the SHA-256 of that UTF-8 image text. Files are normalized to
UTF-8 without a byte-order mark and LF line endings, then compressed with `gzip -n -9`.

No other XML element, attribute, or text value is changed.

## Checksums

| Fixture | Upstream SHA-256 | Derived XML SHA-256 | Deterministic gzip SHA-256 |
| --- | --- | --- | --- |
| `default.tb7.gz` | `06a0d76397c8fcbf032cb05cf832c593b626806c3cfd6f10cdd8a5176d3686e5` | `8d5d369bfb634c0962d5e0fe03b7f53b2c0efda0d99b991708b42bfef3aff7b6` | `7925a08ccf55c1d049433765c5741a44372fec0e34dd7209bc386329cf06a4e1` |
| `Azure Cloud Services.tb7.gz` | `1b5aca6634c31f01944208dabb0cf939915f677fd8ab03f9706a57564ca72cc4` | `a05cb147d2c60f73521aa8923549d37534761e0e3a4a24fcae8a03a554afa737` | `f36363e1156604f99bc20661181431f5eee07bf28e2cb43ed2b7dcd3f5b9a0a2` |
| `MedicalDeviceTemplate.tb7.gz` | `8596a9e83cef0f2c46c100b99fbc6a348a13394273cfb2f02ad9a67999be15ed` | `f89dcae1ee2aaa095311558fa68965437aa60f05e3223bf404c350a6324de0e1` | `f10ef8f862f9cc649bff4cfef2a42727f5a1e76dcc2fe3af52d3d5d299dab988` |

The regression tests verify the compressed fixture checksums before loading them.
