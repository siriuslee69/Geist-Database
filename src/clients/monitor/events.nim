## Events <- bounded UI history and structured debug lines from Geist metadata.
import std/[json, strutils, os]
import runePragmas
import geist/wire

proc eventJson*(e: GeistNetworkEvent): JsonNode {.role: helper.} =
  ## e: public metadata, including all six mask fields selected by the tier.
  var
    m = tierMasks(e.tier)
  result = %*{"at": e.at, "step": e.step, "peer": e.endpoint,
    "subject": e.subject, "mode": e.mode, "tier": $e.tier,
    "session": $e.sessionId, "bytes": e.bytes, "error": e.error,
    "masks": {"kem": toHex(m.kem, 2), "signature": toHex(m.signature, 2),
      "cipher": toHex(m.cipher, 2), "mac": toHex(m.mac, 2),
      "hash": toHex(m.hash, 2), "kdf": toHex(m.kdf, 2)}}

proc writeDebug*(root: string, n: JsonNode) {.role: dataWriter.} =
  ## root/n: persistent, bounded JSON lines; no message bodies or key material.
  var
    path: string = root / "debug.jsonl"
    f: File = nil
  if fileExists(path) and getFileSize(path) > 8 * 1024 * 1024:
    if fileExists(path & ".previous"): removeFile(path & ".previous")
    moveFile(path, path & ".previous")
  if not open(f, path, fmAppend):
    raise newException(IOError, "cannot append Geist debug log")
  defer: f.close()
  f.writeLine($n)
  f.flushFile()
