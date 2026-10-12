# Protocol helper fuzz target

`protocol_helpers_fuzz` exercises offline DNN/FQDN semantics and identity
consumers. It does not decode NAS/GTP messages, perform roundtrips, or call
cryptographic wrappers. This is separate from the wire-decoder coverage in
PRs #4849 and #4852.

## Input contract

Inputs contain one selector byte followed by at most 256 payload bytes. Empty
files and files larger than 257 bytes are rejected. The selector modulo four
chooses the operation:

| Selector | Payload | Calls |
| --- | --- | --- |
| 0 | DNN or network FQDN text | `ogs_dnn_oi_from_fqdn`, `ogs_plmn_id_mcc_from_fqdn`, `ogs_plmn_id_mnc_from_fqdn` |
| 1 | SUPI text | `ogs_supi_to_imsi_bcd` |
| 2 | PEI text | `ogs_pei_is_valid` |
| 3 | One declared-length byte and exactly `sizeof(ogs_nas_mobile_identity_imeisv_t)` identity bytes | `ogs_nas_imeisv_to_bcd` |

Each text input gets a fresh, exact-size allocation and an appended NUL.
Embedded NUL bytes retain normal C-string semantics. Empty strings are passed
as non-NULL buffers. No required pointer argument is NULL. The returned DNN
operator-identifier pointer is borrowed from the input and is not freed
separately. All three FQDN helpers receive the same text, including malformed
text; the MCC/MNC helpers implement their own rejection paths.

SUPI output storage is `OGS_MAX_IMSI_BCD_LEN + 1` (16 bytes), initially zeroed,
with a fresh boolean result. The consumer accepts decimal IMSI payloads of
one through 15 digits, not a universal six-digit minimum. Non-IMSI types can
succeed without producing an IMSI alias; this is not treated as a failure.
PEI validation expects exactly 15 digits for `imei-` or 16 for `imeisv-`.
Neither consumer is preceded by a harness validator that would hide its own
malformed-input paths.

IMEISV input is copied into a fully backed, packed nine-octet object before
the call. Its declared length is independent of the available storage, so
invalid lengths exercise the converter's early rejection safely. Output is
`OGS_MAX_IMEISV_BCD_LEN + 1` (17 bytes), initially zeroed. The converter requires
length nine and even parity; its existing tolerance for unusual filler and
nondecimal nibbles is preserved. Other payload sizes skip this mode. There is
no conversion back to wire format or secondary identity consumer.

Initialization follows `fuzzing.h`; core and NAS logging are suppressed for
expected invalid inputs. Inputs and outputs are not shared between iterations.
No harness assertions impose stronger protocol rules than the callees.

## Corpus

`protocol_helpers_fuzz_seed_corpus.zip` contains 74 selector-prefixed inputs:
23 DNN/FQDN, 20 SUPI, 21 PEI, and 10 IMEISV seeds. It covers realistic
network/DNN suffixes, rightmost `.mnc`
selection, truncated and nonnumeric MCC/MNC labels, IMSI and non-IMSI SUPIs,
valid and malformed PEIs, embedded NUL/high-byte text, the maximum payload
bound, and fully backed IMEISV objects with valid/invalid lengths, parity,
filler, and digit nibbles. Binary IMEISV seeds use the octet layout specified
by the existing `ED2`/`ED3` field declarations, not a cast into ZIP storage.

No dictionary or options file is needed: the short semantic prefixes and
boundary cases are already represented in the corpus, and the input bound
is enforced in the harness.

## Dependencies and registration

The Meson target uses `libproto_dep`, `libnas_common_dep`, `libcore_dep`, the
existing test compile flags, and `lib_fuzzing_engine`. NAS-common pulls in
`libcrypt_dep` transitively through its existing public header and dependency;
the harness calls no security or cryptographic functions. There is no SBI,
MongoDB, network, or daemon initialization in the target.

OSS-Fuzz registration must separately add
`tests/fuzzing/protocol_helpers_fuzz` to the project's explicit Ninja target
list and copy `builddir/tests/fuzzing/protocol_helpers_fuzz` to
`$OUT/protocol_helpers_fuzz`. The existing `*_seed_corpus.zip` copy rule
already matches this archive. Use a source revision containing this harness
and Meson entry, and retain the existing fuzzing-engine/link setup. The SUPI
path allocates through core's configured allocator, so confirm allocator and
sanitizer compatibility, particularly system libtalloc under MSan, before
enabling it for that sanitizer. This work does not change OSS-Fuzz packaging.

## Validation limits

Validation here is static: source/input-schema checks, corpus integrity and
schema checks, editor diagnostics, and whitespace/diff checks. No project
build script, fuzzer build, fuzzer execution, or coverage campaign is run.
Compilation, linking, sanitizer behavior, seed replay, and coverage gains
remain to be verified through OSS-Fuzz after registration.
