# NOA Receipt Glossary

| Term | Meaning |
| --- | --- |
| `noa.receipt/0.1` | Frozen native JSON receipt wire-format identifier; separate from npm package semver and optional COSE envelope version. |
| action identifier (`action.id`) | Identifier of the tool or action. It is not a target reference or invocation identifier. |
| canonical action (`action.canonical`) | Revision-defined risk-table key used by receipt/gate semantics. |
| `paramsHash` | Producer commitment to the parameter-set bytes as defined by the producer; it is not a universal cross-producer digest. |
| `SOURCE_ABSENT` | A fact that a source format does not contain a field or claim. It is distinct from unknown, invalid, or inferred. |
| receipt | Signed statement in the protocol. Its validity does not prove the underlying statement is true. |
| canonicalization | Deterministic conversion to the bytes covered by the receipt hash/signature rules; current native JSON rules use RFC 8785/JCS. |
| conformance profile | Versioned set of requirements, vectors, expected results, runner details, and declaration rules for a specific interoperability claim. |
| independent implementation | An implementation built through genuinely separate implementation and decision paths; language count alone does not establish independence. |
| `PARTIAL` | Outcome indicating incomplete evidence/result. It is not `PASS` and cannot be silently promoted. |
| `NON-CLAIM` | Explicit statement that the system does not assert a property, such as physical completion or exactly-once execution. |
| trust anchor | Key, registry, or root material a verifier uses under an explicit trust policy; cryptographic validity alone does not decide whether it is trusted now. |
| freshness / revocation | Time- and policy-dependent checks about whether a key, claim, or authorization should still be relied upon. |
| COSE / SCITT companion profile | Optional signed-artifact carriage/interoperability layer with its own algorithm and compatibility rules; not a silent replacement for native JSON verification. |
| production-verified | Observed under real production workloads with defined scope and evidence. It is not implied by code, local tests, CI, or package publication. |
