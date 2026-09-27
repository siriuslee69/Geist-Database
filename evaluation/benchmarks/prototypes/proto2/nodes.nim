## ------------------------------------------------------------------
## Node <- variant-encoded unit. 24 B. Never appears in an API signature.
## ------------------------------------------------------------------

import runePragmas

type
  ByteSeq* = seq[uint8]
  KeyId* = uint64
  NameId* = uint16

  NodeKind* = enum
    nkNull, nkText, nkInt, nkFloat, nkBytes, nkSealed

  NodeRole* = enum
    nrField, nrMeta, nrRef, nrKeyPublic, nrKeySealed, nrEvidence

  Sealed* = object
    algo*: uint16
    keyRef*: KeyId
    nonce*: ByteSeq
    tag*: ByteSeq
    cipher*: ByteSeq

  Node* = object
    role*: NodeRole
    nameId*: NameId              ## index into the cluster's name table
    case kind*: NodeKind
    of nkNull:   discard
    of nkText:   text*: string
    of nkInt:    num*: int64
    of nkFloat:  f*: float64
    of nkBytes:  bytes*: ByteSeq
    of nkSealed: sealed*: ref Sealed

  ## NameTable: field names live ONCE per cluster, not once per row.
  NameTable* = object
    names*: seq[string]

  ClusterRole* = enum
    crMeta, crSchema, crKeyLedger, crJournal, crVersion, crEntry

  ClusterMode* = enum
    cmMutable, cmAppend, cmChained

  Cluster* = object
    role*: ClusterRole
    mode*: ClusterMode
    typeName*: string
    id*: uint64
    names*: NameTable
    nodes*: seq[Node]

proc intern*(t: var NameTable, s: string): NameId {.role: truthBuilder.} =
  for i in 0 ..< t.names.len:
    if t.names[i] == s:
      return NameId(i)
  t.names.add s
  result = NameId(t.names.len - 1)

proc name*(t: NameTable, id: NameId): string {.role: parser.} =
  if int(id) < t.names.len: t.names[int(id)] else: ""
