## The Android keyring bridge's JSON layer, run on the desktop. The JNI
## functions around it are Android-only; everything they pass through is here.
import std/[json, os, unittest]
import ../../android/geistvault/src/main/nim/geist_vault_bridge

proc ask(q: JsonNode): (int32, JsonNode) =
  ## q: one request -> its code and parsed answer.
  var code: int32 = vaultCall($q)
  result = (code, parseJson(lastAnswer()))

suite "vault bridge":
  # {.testKind: tkIntegration, covers: "vaultCall|lastAnswer".}
  test "create, save, reopen, unlock and read through JSON":
    var root = getTempDir() / "geist_t_bridge"
    removeDir(root)
    var (code, a) = ask(%*{"op": "create", "root": root, "rings": ["s1", "s2"], "passwords": ["p1", "p2"]})
    check code == 0
    var h = a["handle"].getInt()
    check ask(%*{"op": "replace", "handle": h, "ring": "s1",
      "rows": [{"rowKey": "c1", "kind": "accounts", "body": "ᚠ ✓ 🗝"}]})[0] == 0
    check ask(%*{"op": "save", "handle": h})[0] == 0
    check ask(%*{"op": "close", "handle": h})[0] == 0
    (code, a) = ask(%*{"op": "open", "root": root})
    check code == 0 and a["rings"].len == 2
    h = a["handle"].getInt()
    check ask(%*{"op": "unlock", "handle": h, "ring": "s1", "password": "wrong"})[0] == -2
    check ask(%*{"op": "unlock", "handle": h, "ring": "s1", "password": "p1"})[0] == 0
    (code, a) = ask(%*{"op": "rows", "handle": h, "ring": "s1"})
    check a["rows"][0]["body"].getStr() == "ᚠ ✓ 🗝"
    check ask(%*{"op": "rows", "handle": h, "ring": "s2"})[0] == -1
    (code, a) = ask(%*{"op": "sealed", "handle": h, "ring": "s1", "rowKey": "c1"})
    check code == 0 and a["hex"].getStr().len > 40
    (code, a) = ask(%*{"op": "sealed", "handle": h, "ring": "s2", "rowKey": "c1"})
    check code == 0 and a["hex"].getStr().len == 0
    check ask(%*{"op": "close", "handle": h})[0] == 0

  # {.testKind: tkEdgeCase, covers: "vaultCall".}
  test "bad requests are refused with a code and a reason":
    check ask(%*{"op": "nope", "handle": 999})[0] == -1
    check vaultCall("{not json") == -1
    check parseJson(lastAnswer()).hasKey("error")
    check ask(%*{"op": "open", "root": getTempDir() / "geist_t_bridge_missing"})[0] == -3
