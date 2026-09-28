## Settings files: every option written out, and a hand-edited one read
## back without losing anything.
##
## The three rules the module promises are each asserted directly:
## a missing key is the default, a key the object does not have is KEPT,
## and a value of the wrong kind is the default. The third suite is the
## one that matters most in practice -- it is a person's typo, and the
## file has to survive it.

import runePragmas
import std/[json, os, strutils, tables, unittest]

import geist/doc

type
  Mode = enum
    mQuiet, mLoud

  Net = object
    host*: string
    port*: int
    tiers*: seq[string]

  Friend = object
    notify*: bool
    blocked*: bool
    nickname*: string

  Cfg = object
    name*: string
    mode*: Mode
    ratio*: float
    net*: Net
    friend*: OrderedTable[string, Friend]

proc defaults(): Cfg {.role: configurator.} =
  result.name = "me"
  result.mode = mQuiet
  result.ratio = 1.5
  result.net = Net(host: "127.0.0.1", port: 47655, tiers: @["standard"])
  result.friend = initOrderedTable[string, Friend]()

proc scratch(name: string): string {.role: helper.} =
  result = getTempDir() / "geist_doc_test" / name
  createDir(result.parentDir())

suite "an object becomes a file a person can edit":

  test "every field is written, even the ones left at their default":
    var p = scratch("all.toml")
    removeFile(p)
    check writeDoc(p, defaults()).ok
    var text = readFile(p)
    check "name = \"me\"" in text
    check "mode = \"mQuiet\"" in text
    check "[net]" in text
    check "host = \"127.0.0.1\"" in text
    check "port = 47655" in text
    check "tiers = [\"standard\"]" in text

  test "a float keeps its point, so it reads back as a float":
    var p = scratch("float.toml")
    check writeDoc(p, defaults()).ok
    check "ratio = 1.5" in readFile(p)
    check readDoc(p, defaults()).report.mistyped.len == 0

  test "an enum is written by name, never by number":
    var c = defaults()
    c.mode = mLoud
    var p = scratch("enum.toml")
    check writeDoc(p, c).ok
    check "mode = \"mLoud\"" in readFile(p)
    check readDoc(p, defaults()).value.mode == mLoud

  test "comments land above the field they explain":
    var s = defaultDocStyle()
    s.header = @["Written by the test."]
    s.noteOn("net.port", "the DAC port; 0 picks one")
    var p = scratch("notes.toml")
    check writeDoc(p, defaults(), s).ok
    var
      L = readFile(p).splitLines()
      i = 0
      seen = false
    while i < L.len - 1:
      if L[i].strip() == "# the DAC port; 0 picks one":
        check L[i + 1].strip().startsWith("port =")
        seen = true
      i = i + 1
    check seen
    check readFile(p).startsWith("# Written by the test.")

  test "a named table becomes one section per name":
    var c = defaults()
    c.friend["alice"] = Friend(notify: true, nickname: "Al")
    c.friend["bob"] = Friend(blocked: true)
    var p = scratch("friends.toml")
    check writeDoc(p, c).ok
    var text = readFile(p)
    check "[friend.alice]" in text
    check "[friend.bob]" in text
    check "nickname = \"Al\"" in text

  test "the round trip is faithful":
    var c = defaults()
    c.name = "someone"
    c.mode = mLoud
    c.net.port = 9
    c.net.tiers = @["a", "b"]
    c.friend["alice"] = Friend(notify: true, nickname: "Al")
    var p = scratch("trip.toml")
    check writeDoc(p, c).ok
    var back = readDoc(p, defaults())
    check back.report.ok
    check back.value.name == "someone"
    check back.value.mode == mLoud
    check back.value.net.port == 9
    check back.value.net.tiers == @["a", "b"]
    check back.value.friend["alice"].nickname == "Al"
    check back.value.friend["alice"].notify

suite "a missing key is the default":

  test "an absent file is every default, and not an error":
    var p = scratch("gone.toml")
    removeFile(p)
    var r = readDoc(p, defaults())
    check r.report.ok
    check r.value.name == "me"
    check r.value.net.port == 47655

  test "a trimmed file keeps the defaults it does not mention":
    var p = scratch("trimmed.toml")
    writeFile(p, "name = \"you\"\n")
    var r = readDoc(p, defaults())
    check r.report.ok
    check r.value.name == "you"
    check r.value.net.host == "127.0.0.1"
    check r.value.ratio == 1.5

  test "a missing key is reported but is not a problem":
    var p = scratch("trimmed2.toml")
    writeFile(p, "name = \"you\"\n")
    var r = readDoc(p, defaults())
    check r.report.missing.len > 0
    check not r.report.hasProblems()

suite "a key the object does not have is kept":

  test "it is reported rather than applied":
    var p = scratch("stray.toml")
    writeFile(p, "name = \"you\"\nweird = 1\n")
    var r = readDoc(p, defaults())
    check r.report.ok
    check "weird" in r.report.unknown
    check r.report.hasProblems()

  test "and it survives being written back":
    var p = scratch("stray2.toml")
    writeFile(p, "name = \"you\"\nweird = 1\n\n[nobody]\nhere = true\n")
    var r = readDoc(p, defaults())
    check writeDoc(p, r.value, defaultDocStyle(), r.node).ok
    var text = readFile(p)
    check "weird = 1" in text
    check "[nobody]" in text
    check "name = \"you\"" in text

  test "an unknown section is reported once, not once per key":
    var p = scratch("stray3.toml")
    writeFile(p, "[nobody]\na = 1\nb = 2\nc = 3\n")
    var r = readDoc(p, defaults())
    check r.report.unknown == @["nobody"]

  test "but a stray inside a known section is named in full":
    var p = scratch("stray4.toml")
    writeFile(p, "[net]\nhost = \"h\"\nprotocol = \"udp\"\n")
    var r = readDoc(p, defaults())
    check r.report.unknown == @["net.protocol"]

  test "dropping it is a choice the caller can make":
    var p = scratch("stray5.toml")
    writeFile(p, "weird = 1\n")
    var r = readDoc(p, defaults())
    check writeDoc(p, r.value, defaultDocStyle()).ok
    check "weird" notin readFile(p)

suite "a value of the wrong kind is the default":

  test "a string where a number belongs":
    var p = scratch("bad1.toml")
    writeFile(p, "[net]\nport = \"eighty\"\n")
    var r = readDoc(p, defaults())
    check r.report.ok
    check r.value.net.port == 47655
    check "net.port" in r.report.mistyped

  test "an enum case that does not exist":
    var p = scratch("bad2.toml")
    writeFile(p, "mode = \"mSideways\"\n")
    var r = readDoc(p, defaults())
    check r.value.mode == mQuiet
    check "mode" in r.report.mistyped

  test "an integer is accepted for a float":
    var p = scratch("bad3.toml")
    writeFile(p, "ratio = 2\n")
    var r = readDoc(p, defaults())
    check r.value.ratio == 2.0
    check r.report.mistyped.len == 0

  test "a scalar where a table belongs":
    var p = scratch("bad4.toml")
    writeFile(p, "net = 3\n")
    var r = readDoc(p, defaults())
    check r.value.net.host == "127.0.0.1"
    check "net" in r.report.mistyped

suite "nothing raises":

  test "a syntax error comes back as a report":
    var p = scratch("broken.toml")
    writeFile(p, "name = \nthis is not toml [[[\n")
    var r = readDoc(p, defaults())
    check not r.report.ok
    check r.report.err.len > 0
    check r.value.name == "me"

  test "ensureDoc leaves a broken file exactly as it found it":
    var
      p = scratch("broken2.toml")
      before = "name = \nthis is not toml [[[\n"
    writeFile(p, before)
    var r = ensureDoc(p, defaults())
    check not r.written
    check readFile(p) == before

  test "ensureDoc fills a partial file out to every option":
    var p = scratch("partial.toml")
    writeFile(p, "name = \"you\"\n")
    var r = ensureDoc(p, defaults())
    check r.written
    var text = readFile(p)
    check "name = \"you\"" in text
    check "[net]" in text
    check "port = 47655" in text

suite "json is the same object, a different file":

  test "written and read back":
    var c = defaults()
    c.name = "json"
    c.friend["alice"] = Friend(notify: true)
    var p = scratch("cfg.json")
    check writeDoc(p, c).ok
    check parseJson(readFile(p))["name"].getStr() == "json"
    var back = readDoc(p, defaults())
    check back.report.ok
    check back.value.name == "json"
    check back.value.friend["alice"].notify

  test "the format follows the extension":
    check formatOf("a/b/config.toml") == dfToml
    check formatOf("a/b/config.JSON") == dfJson
    check formatOf("noextension") == dfToml

suite "a key that is not a bare word survives the round trip":
  ## The keys most likely to need quoting are exactly the ones a
  ## per-friend or per-account table is made of: an email address, a
  ## hostname, a name with a space. A header written unquoted looks
  ## plausible and only breaks when it is READ BACK, by which point the
  ## settings have moved into a table nobody looks in.

  test "an address key is quoted in its table header":
    var p = scratch("dotted.toml")
    removeFile(p)
    var c = defaults()
    c.friend["alice@example.com"] = Friend(notify: true, nickname: "Al")
    check writeDoc(p, c).ok
    var text = readFile(p)
    # Unquoted, TOML reads this as friend -> "alice@example" -> "com".
    check "[friend.\"alice@example.com\"]" in text
    check "[friend.alice@example.com]" notin text

  test "and it reads back as the one key it was written from":
    var p = scratch("dotted2.toml")
    removeFile(p)
    var c = defaults()
    c.friend["alice@example.com"] = Friend(notify: true, nickname: "Al")
    check writeDoc(p, c).ok
    var back = readDoc(p, defaults())
    check back.report.ok
    check back.value.friend.len == 1
    check back.value.friend.hasKey("alice@example.com")
    check back.value.friend["alice@example.com"].nickname == "Al"

  test "a key with a space is quoted too":
    var p = scratch("space.toml")
    removeFile(p)
    var c = defaults()
    c.friend["the boss"] = Friend(notify: false, nickname: "B")
    check writeDoc(p, c).ok
    check "[friend.\"the boss\"]" in readFile(p)
    var back = readDoc(p, defaults())
    check back.report.ok
    check back.value.friend.hasKey("the boss")

  test "an ordinary key is still written bare":
    var p = scratch("bare.toml")
    removeFile(p)
    var c = defaults()
    c.friend["alice"] = Friend(notify: true, nickname: "Al")
    check writeDoc(p, c).ok
    # Quoting everything would be safe and unreadable. Only what has to be.
    check "[friend.alice]" in readFile(p)

suite "converting":
  # {.testKind: tkProperty, covers: "convertDoc".}
  test "JSON to TOML and back gives the same document":
    var
      text: string = """{"a": 1, "b": {"c": "x", "d": [1, 2]},""" &
        """ "e": [[1, 2], [3]], "f": [{"g": true}, {"g": false}], "h": 0.5}"""
      toml: tuple[ok: bool, text: string, err: string] =
        convertDoc(text, dfJson, dfToml)
      back: tuple[ok: bool, text: string, err: string] = (false, "", "")
    check toml.ok
    back = convertDoc(toml.text, dfToml, dfJson)
    check back.ok
    check parseJson(back.text) == parseJson(text)

  # {.testKind: tkEdgeCase, covers: "convertDoc, tomlProblem".}
  test "what TOML cannot hold is refused, and named":
    check convertDoc("""{"a": {"b": null}}""", dfJson,
      dfToml).err.contains("a.b is null")
    check convertDoc("""[1, 2]""", dfJson, dfToml).err.contains("table")
    check convertDoc("""{"a": [{"x": 1}, 2]}""", dfJson,
      dfToml).err.contains("mixes")

  # {.testKind: tkEdgeCase, covers: "convertDoc".}
  test "text that is not what it claims says so":
    check not convertDoc("{not json", dfJson, dfToml).ok
    check convertDoc("{not json", dfJson, dfToml).err.contains("not valid JSON")

  # {.testKind: tkIntegration, covers: "convertFile".}
  test "a file converts by its extension, and a refusal writes nothing":
    var
      dir: string = scratch("geist_t_doc_convert")
    createDir(dir)
    writeFile(dir / "in.json", """{"server": {"port": 993}}""")
    check convertFile(dir / "in.json", dir / "out.toml").ok
    check readFile(dir / "out.toml").contains("[server]")
    writeFile(dir / "bad.json", """{"a": null}""")
    check not convertFile(dir / "bad.json", dir / "bad.toml").ok
    check not fileExists(dir / "bad.toml")

  # {.testKind: tkUnit, covers: "toDocText, fromDocText".}
  test "an object as text and back":
    var
      c: Cfg = defaults()
      read: tuple[value: Cfg, report: DocReport] = (defaults(), DocReport())
    c.net.port = 4242
    read = fromDocText(toDocText(c, dfJson), dfJson, defaults())
    check read.report.ok
    check read.value.net.port == 4242
    read = fromDocText(toDocText(c, dfToml), dfToml, defaults())
    check read.value.net.port == 4242
