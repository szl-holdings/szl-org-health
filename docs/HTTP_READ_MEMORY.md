# Bounded HTTP read allocations

The response byte ceiling is a maximum accepted body size, not a requested
allocation size. `request_bytes` now reads at most 1 MiB at a time, preserves
all bytes, and reads one extra byte at the ceiling to reject overflow. The
existing content-length check, HTTPS and redirect validation, credential
stripping, retry policy, and response diagnostics remain in force.

## Reproduction and regression proof

On September 29, 2026, a real `io.BufferedReader` backed by a 4 KiB body was
read with the existing 512 MiB archive ceiling. `tracemalloc` observed
536,875,387 bytes of peak Python allocations from the baseline direct read.
The corrected `request_bytes` returned the identical 4 KiB payload with
1,059,004 peak allocated bytes in the corresponding buffered-reader fixture.
Both figures describe this local fixture, rather than whole-process memory.

The regression suite fails against merged baseline
`e00707bcd5ae4c01de56f1e5297d5480b210e70c` and passes with the change. It
checks allocation pressure, empty and exact-limit bodies, one-byte overflow,
multiple chunks, short raw reads, and rejection before reading an oversized
declared content length. Existing HTTP and archive-integrity contracts also
remain applicable.

The earlier 127-repository receipt retained a `MemoryError` for
`szl-holdings/szl-uds-deployment`. This change removes a reproduced source of
allocation pressure. That historical exception alone does not establish its
precise allocation site or prove complete estate collection after the repair.
A fresh authoritative receipt is required for that claim. Accepted bodies
are still retained in memory, and returning immutable bytes can temporarily
require a second copy; archive and repository ceilings remain enforced.

## Validation

```text
python -m unittest tests.test_http_read_memory tests.test_census tests.test_file_audit tests.test_repository_file_audit_runner -v
python -m unittest discover -s tests -p test_file_audit_line_endings.py -v
```

The first command passed 60 scoped tests; the second passed nine archive
export regressions. Hosted CI executes the complete contract suite and the
container smoke test. This source change does not repair missing or invalid
GitHub App credentials in the scheduled collector.
