## -------------------------------------------------------------------------
## Grant tests <- who may read or write which address
## -------------------------------------------------------------------------
##
##   suite                              what it holds down
##   ---------------------------------  ----------------------------------------
##   "the most specific grant decides"  longest prefix, whole path parts only
##   "defaults and revocation"          nothing granted, then removed
##   "names and addresses"              the bad inputs are refused
##   "the text table"                   encode, decode, damage
##   "the table in its own store"       saved and read back, found or not

import std/[unittest, os, strutils]

import runePragmas
import geist

suite "the most specific grant decides":

  # {.testKind: tkUnit, covers: "rightsAt|grant".}
  test "a longer prefix overrides a shorter one for the same subject":
    var
      T: GrantTable = GrantTable()
    check T.grant("phone", "fjord", {prRead}).ok
    check T.grant("phone", "fjord/mail/alice", {prRead, prWrite}).ok
    check rightsAt(T, "phone", "fjord/mail/alice/inbox") == {prRead, prWrite}
    check rightsAt(T, "phone", "fjord/mail/bob/inbox") == {prRead}
    check rightsAt(T, "phone", "fjord") == {prRead}

  # {.testKind: tkEdgeCase, covers: "covers".}
  test "a prefix covers whole path parts, never a longer word":
    var
      T: GrantTable = GrantTable()
    discard T.grant("nas", "fjord/mail", {prRead})
    check allows(T, "nas", "fjord/mail/alice", prRead)
    check not allows(T, "nas", "fjord/mailbox", prRead)
    check not allows(T, "nas", "fjordish", prRead)

  # {.testKind: tkEdgeCase, covers: "rightsAt".}
  test "a grant to one subject says nothing about another":
    var
      T: GrantTable = GrantTable()
    discard T.grant("phone", "fjord", {prRead})
    check rightsAt(T, "eris", "fjord/mail/alice") == {}
    check rightsAt(T, "phone", "fjord/mail/alice") == {prRead}

  # {.testKind: tkEdgeCase, covers: "normalPath".}
  test "the scheme, the query and a trailing slash do not change the place":
    var
      T: GrantTable = GrantTable()
    discard T.grant("phone", "fjord/mail", {prRead})
    check allows(T, "phone", "geist://fjord/mail/alice/inbox?ttl=4&via=vps",
      prRead)
    check allows(T, "phone", "fjord/mail/alice/", prRead)
    check normalPath("geist://fjord/mail/?x=1") == "fjord/mail"

suite "defaults and revocation":

  # {.testKind: tkUnit, covers: "rightsAt".}
  test "with no grant there are no rights":
    var
      T: GrantTable = GrantTable()
    check rightsAt(T, "phone", "fjord/mail/alice") == {}
    check not allows(T, "phone", "fjord/mail/alice", prRead)

  # {.testKind: tkUnit, covers: "grant".}
  test "an empty rights set removes the grant, and a second grant replaces it":
    var
      T: GrantTable = GrantTable()
    discard T.grant("phone", "fjord", {prRead, prWrite})
    discard T.grant("phone", "fjord", {prRead})
    check T.grants.len == 1
    check rightsAt(T, "phone", "fjord") == {prRead}
    discard T.grant("phone", "fjord", {})
    check T.grants.len == 0
    check rightsAt(T, "phone", "fjord") == {}

suite "the table's folder":

  # {.testKind: tkUnit, covers: "grantsDir".}
  test "the grant table lives in db/grants":
    var
      h = openHome(getTempDir() / "nebel_permission_dir", nrClient).home
    check grantsDir(h) == h.dbDir() / "grants"
    check not grantsDir(h).lastPathPart.contains(".")

suite "names and addresses":

  # {.testKind: tkEdgeCase, covers: "grant|validName".}
  test "a subject or prefix that is not a clean name is refused":
    var
      T: GrantTable = GrantTable()
    check not T.grant("", "fjord", {prRead}).ok
    check not T.grant("phone", "", {prRead}).ok
    check T.grant("ph one", "fjord", {prRead}).err.contains("characters")
    check T.grant("phone", "../etc", {prRead}).err.contains("prefix")
    check T.grant("phone", "/fjord", {prRead}).err.contains("prefix")
    check T.grant("phone", "fjord/*", {prRead}).err.contains("prefix")
    check T.grant("phone", "fjord//mail", {prRead}).err.contains("prefix")
    check T.grants.len == 0

  # {.testKind: tkEdgeCase, covers: "rightsAt".}
  test "a subject named * is refused, so no grant can reach everyone":
    var
      T: GrantTable = GrantTable()
    check not T.grant("*", "fjord", {prRead}).ok
    check rightsAt(T, "phone", "fjord") == {}

suite "the text table":

  # {.testKind: tkRegression, covers: "encodeGrants|decodeGrants".}
  test "the table written as text reads back to the same grants":
    var
      T: GrantTable = GrantTable()
      back: tuple[ok: bool, table: GrantTable, err: string] = (false,
        GrantTable(), "")
    discard T.grant("phone", "fjord/mail/alice", {prRead, prWrite})
    discard T.grant("nas", "fjord", {prRead})
    back = decodeGrants(encodeGrants(T))
    check back.ok
    check back.table.grants == T.grants
    check encodeGrants(T).contains("phone\tfjord/mail/alice\tread,write")

  # {.testKind: tkEdgeCase, covers: "decodeGrants".}
  test "one damaged line refuses the whole table, never half of it":
    check not decodeGrants("phone\tfjord\tread\nnas\tfjord").ok
    check decodeGrants("phone\tfjord\tread\nnas\tfjord").err.contains("line 2")
    check not decodeGrants("phone\tfjord\tsing").ok
    check not decodeGrants("phone\t../fjord\tread").ok
    check decodeGrants("").ok

suite "the table in its own store":

  # {.testKind: tkIntegration, covers: "saveGrants|loadGrants".}
  test "a saved table is read back by a new process, and a missing one is empty":
    var dir = getTempDir() / "nebel_permission_test"
    removeDir(dir)
    var
      T: GrantTable = GrantTable()
      got: tuple[ok: bool, found: bool, table: GrantTable, err: string] =
        (false, false, GrantTable(), "")
      none: tuple[ok: bool, found: bool, table: GrantTable, err: string] =
        (false, false, GrantTable(), "")
    none = loadGrants(dir)
    check none.ok
    check not none.found
    discard T.grant("phone", "fjord/mail/alice", {prRead, prWrite})
    check saveGrants(dir, T).ok
    got = loadGrants(dir)
    check got.ok
    check got.found
    check got.table.grants == T.grants
    check allows(got.table, "phone", "fjord/mail/alice", prWrite)
    removeDir(dir)
