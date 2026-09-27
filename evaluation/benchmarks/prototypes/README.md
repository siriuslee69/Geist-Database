# Measurement prototypes

Throwaway programs that produced the numbers in
`docs/DESIGN_RATIONALE.md`.
They are kept so the numbers can be re-derived rather than trusted.

| folder | produced |
|---|---|
| `proto2/` | variant-node sizing (24 B/node), name interning |
| `proto3/` | packed-row vs node comparison: memory, allocations, field-read timing |
| `proto4/` | file header + cluster index, partial reads, single-row seek |
| `proto5/` | readOptimize histogram rule, ledger sizing by batch N, Merkle path cost, epoch wrap |

They are standalone: compile inside their own folder. They are NOT part of
`nimble runBenchmarks` -- no file here starts with `bench` -- because they
measured shapes Geist did not end up with; `bench_geist.nim` one level up
measures the one it did.

    cd evaluation/benchmarks/prototypes/proto3 && nim c -r -d:release measure.nim
