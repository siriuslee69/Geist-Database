## -------------------------------------------------------------------------
## Wire row tests <- a row that leaves for a peer carries its long text whole
## -------------------------------------------------------------------------
##
## A stored row may keep a long value in a sidecar. The row a peer receives must
## not be a reference the peer cannot follow, so wireRow writes such a value back
## in. These tests hold down what is written back, and what is not.
##
##   suite                             what it holds down
##   --------------------------------  ------------------------------------------
##   "a row on the wire"               a long text in a sidecar is written back
##                                     and reads whole; a short row is unchanged
##   "what stays a reference"          a reference column, and a payload that
##                                     cannot be read, go out as references

import std/[os, strutils, tables, unittest]

import runePragmas
import geist/types
import geist/row
import geist/dynamic
import geist/sidecar

proc storeIn(root: string): SidecarStore {.role: configurator.} =
  ## A store whose payloads go to one folder, with a small threshold.
  result = initSidecarRoots(@[root / sidecarFolderName], 64'u32)

suite "a row on the wire":
  # {.testKind: tkUnit.}
  test "a long text kept in a sidecar is written back, and reads back whole":
    var
      root = getTempDir() / "geist_t_wire_text"
      long = repeat("w", 3000)
      store: SidecarStore
      schema: Schema
      built: tuple[ok: bool, data: ByteSeq, err: string]
      wire: Row
    removeDir(root)
    createDir(root)
    store = storeIn(root)
    schema = parseSchemaSpec("Doc", "id:int,body:text").s
    built = buildRow(schema, {"id": "7", "body": long}.toTable, store, 0)
    check built.ok
    # Stored: the row keeps a reference, not the text.
    check schema.isExternal(built.data, fieldOffsets(schema, built.data), 1)
    wire = wireRow(schema, Row(data: built.data), store)
    check not schema.isExternal(wire.data, fieldOffsets(schema, wire.data), 1)
    check renderRow(schema, wire.data) == @["7", long]

  # {.testKind: tkEdgeCase.}
  test "a row with nothing in a sidecar goes out unchanged":
    var
      root = getTempDir() / "geist_t_wire_plain"
      store: SidecarStore
      schema: Schema
      built: tuple[ok: bool, data: ByteSeq, err: string]
      wire: Row
    removeDir(root)
    createDir(root)
    store = storeIn(root)
    schema = parseSchemaSpec("Doc", "id:int,body:text").s
    built = buildRow(schema, {"id": "3", "body": "short"}.toTable, store, 0)
    check built.ok
    wire = wireRow(schema, Row(data: built.data), store)
    check wire.data == built.data

suite "what stays a reference":
  # {.testKind: tkEdgeCase.}
  test "a reference column stays a reference, while the text beside it is written back":
    var
      root = getTempDir() / "geist_t_wire_ref"
      store: SidecarStore
      schema: Schema
      built: tuple[ok: bool, data: ByteSeq, err: string]
      wire: Row
      hex = newString(64)
    removeDir(root)
    createDir(root)
    store = storeIn(root)
    for i in 0 ..< hex.len:
      hex[i] = 'b'
    schema = parseSchemaSpec("Doc", "id:int,body:text,file:ref").s
    built = buildRow(schema, {"id": "1", "body": repeat("r", 2000),
      "file": "sidecar:" & hex}.toTable, store, 0)
    check built.ok
    wire = wireRow(schema, Row(data: built.data), store)
    check renderRow(schema, wire.data)[1] == repeat("r", 2000)
    check decodeRef(schema.rawAt(wire.data, fieldOffsets(schema, wire.data), 2)).target ==
      rtSidecar

  # {.testKind: tkEdgeCase.}
  test "a payload that cannot be read stays a reference, and is not guessed":
    var
      root = getTempDir() / "geist_t_wire_gone"
      store: SidecarStore
      schema: Schema
      built: tuple[ok: bool, data: ByteSeq, err: string]
      wire: Row
    removeDir(root)
    createDir(root)
    store = storeIn(root)
    schema = parseSchemaSpec("Doc", "id:int,body:text").s
    built = buildRow(schema, {"id": "5", "body": repeat("g", 2000)}.toTable, store, 0)
    check built.ok
    removeDir(root)
    wire = wireRow(schema, Row(data: built.data), store)
    check wire.data == built.data
