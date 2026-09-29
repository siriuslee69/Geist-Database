## nextOption: the one way every Geist program reads its command line.

import std/unittest

import geist/args

suite "one option at a time":
  # {.testKind: tkUnit, covers: "nextOption".}
  test "--key value, --key=value, a flag and a bare word":
    var
      argv: seq[string] = @["--path", "db", "--limit=5", "--quiet", "list"]
      s: OptionStep = nextOption(argv, 0, ["quiet"])
    check s == ("path", "db", false, 1)
    check nextOption(argv, 2, ["quiet"]) == ("limit", "5", false, 2)
    check nextOption(argv, 3, ["quiet"]) == ("quiet", "", false, 3)
    check nextOption(argv, 4, ["quiet"]) == ("", "list", true, 4)

  # {.testKind: tkEdgeCase, covers: "nextOption".}
  test "an option that needs a value and is last says so":
    expect ValueError:
      discard nextOption(@["--path"], 0, [])

  # {.testKind: tkEdgeCase, covers: "nextOption".}
  test "an = at the very start is part of the name, not a split":
    check nextOption(@["--=x", "y"], 0, []) == ("=x", "y", false, 1)
