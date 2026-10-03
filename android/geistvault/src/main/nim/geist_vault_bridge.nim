## ---------------------------------------------------------------------
## Geist vault bridge <- keyrings for Android, called straight from Kotlin
## ---------------------------------------------------------------------
##
##   Kotlin (GeistVaultNative)            Nim (this file)
##   -------------------------            -------------------------------
##   call(request: ByteArray): Int   ->   Java_..._call   -> vaultCall(op)
##   answer(): ByteArray             <-   Java_..._answer <- last answer
##
## Kotlin reaches native code only through JNI: a function with a fixed
## name (Java_<package>_<class>_<method>) that reads and makes Java arrays
## through the JNIEnv table. Those two functions live at the bottom of this
## file; the JNIEnv table is imported from the NDK's own jni.h, so its
## layout is the header's, not a copy of it. No C file is involved.
##
## Every request and answer is UTF-8 JSON in raw bytes. One entry point
## means no per-operation symbols to keep in step with Kotlin, and no JNI
## string conversion (JNI's "modified UTF-8" mangles emoji and runes;
## raw bytes do not).
##
##   request                                         answer (code 0)
##   ----------------------------------------------  ----------------------------
##   {"op":"create","root","rings":[..],"passwords"}  {"handle":n}
##   {"op":"open","root"}                             {"handle":n,"rings":[..]}
##   {"op":"unlock","handle","ring","password"}      {}
##   {"op":"rows","handle","ring"}                   {"rows":[{"rowKey","kind","body"}]}
##   {"op":"replace","handle","ring","rows":[..]}    {}
##   {"op":"password","handle","ring","password"}    {}
##   {"op":"save","handle"}                          {}
##   {"op":"lock","handle","ring"} / {"op":"close","handle"}   {}
##
## A failure returns a negative code and {"error": text}:
##   -1 the request itself was wrong     -2 wrong password or damaged ring
##   -3 the disk said no
##
## Threading: Android calls in on its own threads. A single lock makes the
## calls one-at-a-time; a vault is opened and saved far too rarely for
## that to matter. Build with -d:useMalloc: Nim's own allocator is per
## thread and a JVM thread never set one up (see the build script).

import std/[json, locks, strutils]

import runePragmas
import geist

type
  Opened {.role: truthState, expectedCount: [0, 8], lifeCycle: lcSession.} = ref object
    ## One open keyring set, named to Kotlin by its handle number.
    handle: int
    rings: Keyrings

var
  gate: Lock = default(Lock)
  opened: seq[Opened] = @[]
  nextHandle: int = 1
  answer: string = ""

initLock(gate)

proc reply(code: int32, body: JsonNode): int32 {.role: helper.} =
  ## code/body: kept as the answer Kotlin fetches next; code is returned.
  answer = $body
  result = code

proc failure(code: int32, text: string): int32 {.role: helper.} =
  ## code/text: a refusal, in the shape every failure takes.
  result = reply(code, %*{"error": text})

proc find(h: int): Opened {.role: parser.} =
  ## h: a handle from create/open. nil when closed or never given out.
  for o in opened:
    if o.handle == h:
      return o
  result = nil

proc rowsJson(R: seq[RingRow]): JsonNode {.role: helper.} =
  ## R: rows as the JSON array Kotlin reads.
  result = newJArray()
  for r in R:
    result.add %*{"rowKey": r.rowKey, "kind": r.kind, "body": r.body}

proc rowsOf(n: JsonNode): seq[RingRow] {.role: parser.} =
  ## n: the JSON array Kotlin sent. Missing fields read as empty text.
  for r in n.getElems():
    result.add RingRow(rowKey: r{"rowKey"}.getStr(), kind: r{"kind"}.getStr(), body: r{"body"}.getStr())

proc strings(n: JsonNode): seq[string] {.role: parser.} =
  ## n: a JSON array of strings.
  for s in n.getElems():
    result.add s.getStr()

proc keep(K: sink Keyrings): int32 {.role: actor.} =
  ## K: a freshly opened set, handed a new handle.
  var
    o: Opened = Opened(handle: nextHandle, rings: K)
    names: JsonNode = newJArray()
  nextHandle = nextHandle + 1
  opened.add o
  for r in o.rings.rings:
    names.add %r.name
  result = reply(0, %*{"handle": o.handle, "rings": names})

proc onRing(q: JsonNode, o: Opened): int32 {.role: orchestrator.} =
  ## q: a request naming one ring of the open set o.
  var
    ring: string = q{"ring"}.getStr()
    r: tuple[ok: bool, err: string] = (false, "")
  case q{"op"}.getStr()
  of "unlock":
    r = o.rings.unlock(ring, q{"password"}.getStr())
    result = if r.ok: reply(0, newJObject()) else: failure(-2, r.err)
  of "rows":
    result = reply(0, %*{"rows": rowsJson(o.rings.rows(ring))})
  of "replace":
    o.rings.replaceAll(ring, rowsOf(q{"rows"}))
    result = reply(0, newJObject())
  of "password":
    o.rings.changePassword(ring, q{"password"}.getStr())
    result = reply(0, newJObject())
  of "lock":
    o.rings.lock(ring)
    result = reply(0, newJObject())
  of "sealed":
    # Works on a locked ring: the row's stored bytes, still sealed.
    result = reply(0, %*{"hex": toHex(cast[string](o.rings.sealedRow(ring, q{"rowKey"}.getStr())))})
  else:
    result = failure(-1, "unknown op " & q{"op"}.getStr())

proc onSet(q: JsonNode): int32 {.role: orchestrator.} =
  ## q: a request about a whole set: save, close, or anything ring-level.
  var
    o: Opened = find(q{"handle"}.getInt())
    r: tuple[ok: bool, err: string] = (false, "")
  if o == nil:
    return failure(-1, "no open keyring set with that handle")
  case q{"op"}.getStr()
  of "save":
    r = o.rings.save()
    result = if r.ok: reply(0, newJObject()) else: failure(-3, r.err)
  of "close":
    o.rings.close()
    opened.delete(opened.find(o))
    result = reply(0, newJObject())
  else:
    result = onRing(q, o)

proc handle(q: JsonNode): int32 {.role: orchestrator.} =
  ## q: one parsed request.
  case q{"op"}.getStr()
  of "create":
    result = keep(createKeyrings(q{"root"}.getStr(), strings(q{"rings"}), strings(q{"passwords"})))
  of "open":
    result = keep(openKeyrings(q{"root"}.getStr()))
  of "names":
    result = reply(0, %*{"rings": ringNames(q{"root"}.getStr())})
  else:
    result = onSet(q)

proc vaultCall*(text: string): int32 {.role: orchestrator.} =
  ## text: one UTF-8 JSON request. Returns the answer's code; the answer
  ## itself is read with `lastAnswer`.
  withLock gate:
    try:
      result = handle(parseJson(text))
    except JsonParsingError, KeyError, ValueError:
      result = failure(-1, getCurrentExceptionMsg())
    except IOError, OSError:
      result = failure(-3, getCurrentExceptionMsg())
    except CatchableError:
      result = failure(-3, getCurrentExceptionMsg())

proc lastAnswer*(): string {.role: parser.} =
  ## The JSON answer to the most recent call.
  withLock gate:
    result = answer

## ------------------------------ JNI ----------------------------------
##
## Only the four JNIEnv functions used here are named; `importc` with the
## header makes the C compiler place them, so the table's real layout
## comes from jni.h. `incompleteStruct` says the other ~230 entries exist.

when defined(android):
  type
    JByteArray = pointer
    JNIEnv = ptr ptr JNINativeInterface
    JNINativeInterface {.importc: "struct JNINativeInterface", header: "<jni.h>",
        incompleteStruct.} = object
      GetArrayLength: proc (env: JNIEnv, a: JByteArray): int32 {.cdecl.}
      GetByteArrayRegion: proc (env: JNIEnv, a: JByteArray, start, n: int32, buf: pointer) {.cdecl.}
      NewByteArray: proc (env: JNIEnv, n: int32): JByteArray {.cdecl.}
      SetByteArrayRegion: proc (env: JNIEnv, a: JByteArray, start, n: int32, buf: pointer) {.cdecl.}

  proc Java_com_siriuslee_geist_GeistVaultNative_call(env: JNIEnv, cls: pointer,
      request: JByteArray): int32 {.exportc, cdecl, dynlib, role: dataFetcher.} =
    ## env/cls: supplied by the JVM. request: the UTF-8 JSON bytes.
    var
      n: int32 = env[].GetArrayLength(env, request)
      text: string = newString(n)
    if n > 0:
      env[].GetByteArrayRegion(env, request, 0, n, addr text[0])
    result = vaultCall(text)

  proc Java_com_siriuslee_geist_GeistVaultNative_answer(env: JNIEnv,
      cls: pointer): JByteArray {.exportc, cdecl, dynlib, role: dataWriter.} =
    ## env/cls: supplied by the JVM. Returns the last answer as a new array.
    var
      a: string = lastAnswer()
    result = env[].NewByteArray(env, int32(a.len))
    if result != nil and a.len > 0:
      env[].SetByteArrayRegion(env, result, 0, int32(a.len), addr a[0])
