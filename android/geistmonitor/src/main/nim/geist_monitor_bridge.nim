## Android bridge <- native Geist API calls, byte arrays preserve UTF-8.
import std/[json, locks]
import runePragmas
import ../../../../../src/clients/monitor/[runtime, provision, page]

var
  gate: Lock = default(Lock)

initLock(gate)

proc nativeRequest*(root, request: string): string {.role: orchestrator.} =
  ## root/request: app-private files and a command from the local WebView.
  var
    q: JsonNode = nil
  acquire(gate)
  defer: release(gate)
  try:
    q = parseJson(request)
    case q{"op"}.getStr()
    of "page": return monitorPage()
    of "provision":
      provisionDevice(root, "phone")
      return "{\"ok\":true}"
    of "import-psk":
      importSharedKey(root, root & "/shared.words")
      return "{\"ok\":true}"
    else: discard
    startMonitorRuntime(root)
    result = monitorRuntimeCall(request)
  except CatchableError as exc:
    result = $(%*{"ok": false, "error": exc.msg})

when defined(android):
  {.compile: "../../../../geistkeystore/src/main/cpp/geist_keystore_jni.c".}
  type
    JByteArray = pointer
    JNIEnv = ptr ptr JNINativeInterface
    JNINativeInterface {.importc: "struct JNINativeInterface", header: "<jni.h>",
        incompleteStruct.} = object
      GetArrayLength: proc(env: JNIEnv, a: JByteArray): int32 {.cdecl.}
      GetByteArrayRegion: proc(env: JNIEnv, a: JByteArray, start, n: int32, buf: pointer) {.cdecl.}
      NewByteArray: proc(env: JNIEnv, n: int32): JByteArray {.cdecl.}
      SetByteArrayRegion: proc(env: JNIEnv, a: JByteArray, start, n: int32, buf: pointer) {.cdecl.}

  proc readBytes(env: JNIEnv, a: JByteArray): string {.role: dataFetcher.} =
    ## env/a: JNI bytes as ordinary UTF-8, including non-BMP characters.
    var
      n: int32 = env[].GetArrayLength(env, a)
    result = newString(n)
    if n > 0: env[].GetByteArrayRegion(env, a, 0, n, addr result[0])

  proc Java_com_siriuslee_geist_monitor_MonitorNative_call(env: JNIEnv,
      cls: pointer, root, request: JByteArray): JByteArray {.
      exportc, cdecl, dynlib, role: orchestrator.} =
    ## env/cls/root/request: one serialized call from Kotlin to Geist.
    var
      answer: string = nativeRequest(readBytes(env, root), readBytes(env, request))
    result = env[].NewByteArray(env, int32(answer.len))
    if result != nil and answer.len > 0:
      env[].SetByteArrayRegion(env, result, 0, int32(answer.len), addr answer[0])
