import std/[random, math, strutils]
import ./stats

when isMainModule:
  randomize(42)
  var
    rows = 100_000
    title: FieldStats  = FieldStats(field: "title", width: 8, rows: rows)
    body: FieldStats   = FieldStats(field: "body", width: 8, rows: rows)
    code: FieldStats   = FieldStats(field: "code", width: 8, rows: rows)
    blobf: FieldStats  = FieldStats(field: "payload", width: 8, rows: rows)

  for i in 0 ..< rows:
    title.lens.add 9 + rand(8)               # 9..17  : just over the line
    body.lens.add 40 + rand(400)             # 40..440: genuinely large
    code.lens.add (if rand(100) < 3: 12 else: 6)  # mostly fits
    blobf.lens.add 32                        # fixed 32B hash, always spills

  echo "readOptimize report (minRate=0.25, maxInline=256):"
  title.report()
  body.report()
  code.report()
  blobf.report()

  echo "\nIoT row, no text fields at all:"
  var
    iot = @[("deviceId", 8), ("metric", 8), ("capturedAt", 8), ("value", 8)]
    w = 0
  for f in iot: w = w + f[1]
  echo "  4 fixed slots -> ", w, " B/row, overflow region = 0 B, 1 allocation"
  echo "  1M rows = ", formatFloat((w*1_000_000)/(1024*1024), ffDecimal, 1),
    " MiB contiguous, memory-mappable, zero pointer chasing"
