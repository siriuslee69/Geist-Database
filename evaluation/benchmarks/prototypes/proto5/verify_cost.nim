import runePragmas
import std/[math, strutils]

const
  rows      = 1_000_000
  encCols   = 4
  rowBytes  = 100          ## ciphertext bytes per row per column

proc mib(n: float): string {.
    role: helper.} = formatFloat(n / (1024*1024), ffDecimal, 2) & " MiB"

## tuple layouts
const
  storedNonce  = 2 + 8 + 12 + 16      ## algo,keyRef,nonce,tag      = 38
  epoch32      = 2 + 8 + 4  + 16      ## algo,keyRef,epoch32,tag    = 30
  epoch64      = 2 + 8 + 8  + 16      ## algo,keyRef,epoch64,tag    = 34

proc ledger(tupleB, n: int): float {.role: MetaRole.math.} =
  float(((rows + n - 1) div n) * encCols * tupleB)

when isMainModule:
  echo "ledger size by tuple layout (", rows, " rows, ", encCols, " cols):"
  echo "  N   stored-nonce(38)   epoch32(30)   epoch64(34)"
  for n in [10, 20, 100, 1000]:
    echo "  ", align($n, 4), "  ", align(mib(ledger(storedNonce, n)), 14),
      "  ", align(mib(ledger(epoch32, n)), 12),
      "  ", align(mib(ledger(epoch64, n)), 12)

  echo "\nverification work to read ONE row (batch N, ", rowBytes, " B/row):"
  echo "  N     batch-MAC bytes   merkle path (32B x log2 N)   ratio"
  for n in [10, 20, 100, 1000]:
    var
      whole = n * rowBytes
      path  = int(ceil(log2(float(n)))) * 32
    echo "  ", align($n, 4), "  ", align($whole & " B", 15),
      "  ", align($path & " B", 24), "   ",
      formatFloat(whole / path, ffDecimal, 1), "x less"

  echo "\nepoch32 wrap at sustained rewrite rates (one hot batch):"
  for r in [10, 100, 1000, 10_000]:
    var days = (4294967296.0 / float(r)) / 86400.0
    echo "  ", align($r, 6), " rewrites/s -> wraps in ",
      formatFloat(days, ffDecimal, 1), " days"
  echo "  epoch64 at 10k/s      -> wraps in ",
    formatFloat((18446744073709551616.0 / 10000.0) / (86400.0*365.0), ffDecimal, 0),
    " years"
