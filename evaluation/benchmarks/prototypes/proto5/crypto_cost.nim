## Batch-encryption metadata overhead: (algo,keyRef,nonce,tag) per batch/column
import runePragmas
import std/strutils

const
  algoB = 2
  keyRefB = 8
  nonceB = 12
  tagB = 16
  tupleB = algoB + keyRefB + nonceB + tagB     # 38 B

proc ledgerBytes*(rows, batchN, encCols: int): int {.role: math.} =
  var batches = (rows + batchN - 1) div batchN
  result = batches * encCols * tupleB

proc mib(n: int): string {.
    role: helper.} = formatFloat(n / (1024*1024), ffDecimal, 2) & " MiB"

when isMainModule:
  const rows = 1_000_000
  echo "keyref ledger size, ", rows, " rows, 4 encrypted columns, ",
    tupleB, " B per (batch,column):"
  for n in [1, 10, 20, 100, 1000]:
    echo "  N=", align($n, 5), "  batches=", align($((rows+n-1) div n), 8),
      "  ledger=", align(mib(ledgerBytes(rows, n, 4)), 10),
      "  read amplification=", n, "x"
