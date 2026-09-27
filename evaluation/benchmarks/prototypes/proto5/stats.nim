## -------------------------------------------------------------------
## Overflow statistics + the readOptimize decision rule
## -------------------------------------------------------------------
##  For field f with inline width w:
##    rate   = overflowing / rows
##    p95    = 95th percentile of value length
##    cost(w) = rows*w  +  sum(len(v)) for v that do not fit w
##  Widen iff cost(w') < cost(w) for w' = ceil8(p95), and rate > minRate.
## -------------------------------------------------------------------

import runePragmas
import std/[algorithm, math, strutils]

type
  FieldStats* = object
    field*: string
    width*: int          ## current inline width in bytes
    rows*: int
    lens*: seq[int]      ## value lengths seen

proc overflowing*(s: FieldStats): int {.role: MetaRole.math.} =
  for L in s.lens:
    if L > s.width: result.inc

proc rate*(s: FieldStats): float {.role: MetaRole.math.} =
  if s.rows == 0: 0.0 else: overflowing(s) / s.rows

proc avgOverage*(s: FieldStats): float {.role: MetaRole.math.} =
  var
    t = 0
    n = 0
  for L in s.lens:
    if L > s.width: t = t + (L - s.width); n.inc
  if n == 0: 0.0 else: t / n

proc percentile*(s: FieldStats, p: float): int {.role: MetaRole.math.} =
  if s.lens.len == 0: return 0
  var v = s.lens
  v.sort()
  var i = int(floor(p * float(v.len - 1)))
  result = v[i]

proc ceil8(n: int): int {.role: MetaRole.math.} = ((n + 7) div 8) * 8

proc cost*(s: FieldStats, w: int): int {.role: MetaRole.math.} =
  ## Bytes for this field across the whole cluster at inline width w.
  result = s.rows * w
  for L in s.lens:
    if L > w: result = result + L        # spills to the overflow region

proc suggestWidth*(s: FieldStats, minRate = 0.25, maxInline = 256): int {.
    role: MetaRole.math.} =
  ## Returns the recommended inline width, or the current one to keep.
  result = s.width
  if s.rate() <= minRate: return
  var w2 = ceil8(s.percentile(0.95))
  if w2 > maxInline: return              # genuinely large -> keep in overflow
  if s.cost(w2) < s.cost(s.width): result = w2

proc report*(s: FieldStats) {.role: dataWriter.} =
  var w2 = s.suggestWidth()
  echo "  ", alignLeft(s.field, 12),
    "w=", align($s.width, 4),
    "  overflow=", align($s.overflowing(), 6),
    " (", align(formatFloat(s.rate()*100, ffDecimal, 1), 5), "%)",
    "  avgOver=", align(formatFloat(s.avgOverage(), ffDecimal, 1), 6),
    "  p95=", align($s.percentile(0.95), 4),
    "  cost=", align($s.cost(s.width), 9),
    if w2 != s.width:
      "  -> WIDEN to " & $w2 & " (cost " & $s.cost(w2) & ")"
    else: "  -> keep"
