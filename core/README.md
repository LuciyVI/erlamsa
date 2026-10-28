# EFZ local mutation core

This is a separate, dependency-free Rebar3 application inside the Erlamsa
repository. It does not start `erlamsa_app`, install the root application's
dependencies, create services, timers, named ETS tables, or campaign state.
No Erlamsa sources are compiled into the EFZ target application.

## Build and test

From the `core/` directory on Erlang/OTP 27 or newer:

```sh
ERL_FLAGS='+S 2:2' rebar3 compile
ERL_FLAGS='+S 2:2' rebar3 eunit
ERL_FLAGS='+S 2:2' rebar3 xref
ERL_FLAGS='+S 2:2' rebar3 dialyzer
```

The Rebar profile has no dependencies and treats compiler warnings as errors.
The Dialyzer base PLT defaults to `/tmp/erlamsa-core-base-plts`; override it
with `rebar3 dialyzer --base-plt-location PATH` when needed. The core API is
`erlamsa_core:prepare/2`, `erlamsa_core:mutate/3`, and `versions/0`.

## Supported bounded operations

The catalogue includes byte flip/insert/drop, block repeat/drop/swap, line
repeat/drop/swap, decimal number changes, delimiter and valid Unicode
insertion, bounded primitive JSON value edits, insertion of a comment node in
a balanced tag-shaped SGML/XML-like input, canonical Base64, gzip and zlib
wrappers, stored (method 0) ZIP entries, and length/XOR8/CRC32 fields.
`once`, `many`, `burst`, and `skip` patterns are request scoped. Weights are
validated and fixed in the immutable prepared context.

The JSON walker validates bounded JSON syntax and mutates a primitive value;
it does not implement every upstream JSON tree transform. The SGML helper
handles balanced simple tags and inserts a comment node; entities, DTDs,
processing instructions, and full SGML grammar are excluded. ZIP supports
single-disk stored entries only. Deflate entries, encryption, data descriptors,
Zip64, unsafe names, and archive comments are skipped. ZIP metadata and CRCs
are checked before entry slices are made, and no ZIP decompression is run.

Gzip/zlib decoding uses `zlib:safeInflate/2` and accepts output only while the
configured unpacked-byte and expansion-ratio limits hold. OTP emits bounded
16 KiB inflate chunks on the validated OTP 27 runtime. The caller runs each
request in EFZ's disposable Linux VM. These checks do not establish a hard
whole-VM memory quota. Gzip output uses OTP's zero-mtime header; exact compressed
bytes are guaranteed only for the same OTP/ERTS and zlib implementation.

Length/checksum mutation requires either an explicit field map or one unique
supported heuristic. The heuristic only recognizes a length field at byte
offset 0..3 whose value equals the remaining payload length, and trailing
XOR8/CRC32 over a contiguous range beginning in the first 31 bytes. This is a
layout guess, not protocol inference. `preserve`, `perturb`, and `mixed` are
recorded in bounded metadata. `field_operator` selects the payload mutation;
it defaults to `byte_flip`.

The API uses an explicit SplitMix64 state derived only from the request's
three-word seed. A request has no dependence on previous requests, target RNG,
time, process dictionary, application startup, or persistent score. Contexts
contain only validated configuration and versions. Raw target replay does not
need this application.

## Upstream and licensing

This fork is based on upstream Erlamsa commit
`4a844bcd1083e3278c10405bb415a32871b216c3`. Upstream history and its root MIT
`LICENSE` are retained. The core files are a bounded EFZ adapter implementation
and do not copy the upstream parser or mutator source files. Upstream-derived
operator names are documented in EFZ's `docs/erlamsa-integration.md`.
