# Origin and implementation scope

The new independent implementation is authored by **dhtfish98** (package version **0.1.2**). Upstream works retain their original attribution and license notices in this document and `UPSTREAM_LICENSE`.

DsseEnvelopeReview independently implements this selected scope: Ed25519 DSSE v1 envelope verification against explicit pinned public keys, expected payload type and independent-key threshold.

The research source is [secure-systems-lab/go-securesystemslib](https://github.com/secure-systems-lab/go-securesystemslib) at fixed commit `2bdfda1553aeb4f67541cb8e6f5ec7b212f4503a`. Source archive SHA-256: `d96408990dd6e9ef7fab30f8a1235f30d3b2f82ba4975429e362d5092b7efa67`. Its license is MIT; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [dsse/envelope.go](https://github.com/secure-systems-lab/go-securesystemslib/blob/2bdfda1553aeb4f67541cb8e6f5ec7b212f4503a/dsse/envelope.go) — SHA-256 `9cfc1986d355de9d812d8c97340bfdea818f8925ccb0b55477747d3b85fe1a4f`.
- [dsse/verify.go](https://github.com/secure-systems-lab/go-securesystemslib/blob/2bdfda1553aeb4f67541cb8e6f5ec7b212f4503a/dsse/verify.go) — SHA-256 `7cfd91ec1eae9fefd0f75c9f302c6f72424ded06b15a213d50a23afe23109fe5`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on DSSE envelope/PAE serialization, key hint versus independent signer threshold. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `envelope` contains standard padded-base64 `payload`, UTF-8 `payloadType`, and `signatures` with `sig` and optional `keyid`. Required `trusted_keys` is a bounded list of pinned public PEM Ed25519 keys; required `expected_payload_type` and `threshold` bind the intended content type and independent key count. Every supplied signature must validate. The unauthenticated `keyid` is ignored for authority. Payload bytes are never executed or printed.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.
