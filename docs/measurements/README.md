# Measurement prototypes

Throwaway programs that produced the numbers in `../DESIGN_RATIONALE.md`.
They are kept so the numbers can be re-derived rather than trusted.

| folder | produced |
|---|---|
| `proto2/` | variant-node sizing (24 B/node), name interning |
| `proto3/` | packed-row vs node comparison: memory, allocations, field-read timing |
| `proto4/` | file header + cluster index, partial reads, single-row seek |
| `proto5/` | readOptimize histogram rule, ledger sizing by batch N, Merkle path cost, epoch wrap |

They are standalone: compile inside their own folder.

    cd docs/measurements/proto3 && nim c -r -d:release --mm:orc bench.nim
