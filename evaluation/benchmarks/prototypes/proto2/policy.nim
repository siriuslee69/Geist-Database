## -------------------------------------------------------------
## Policy pass <- sealing is a pass over nodes, not a type variant
## -------------------------------------------------------------

import ./nodes

type
  FieldPolicy* = object
    field*: string
    seal*: bool
    indexed*: bool

proc sealsField(P: seq[FieldPolicy], nm: string): bool =
  for p in P:
    if p.field == nm: return p.seal

proc sealed1(n: Node, key: ByteSeq, keyRef: KeyId): Node =
  ## A variant node cannot mutate its discriminator, so sealing
  ## RECONSTRUCTS the node. That is a feature: it is impossible to
  ## end up with a half-sealed node carrying stale plaintext slots.
  var plain: ByteSeq = @[]
  case n.kind
  of nkText:  (for c in n.text: plain.add uint8(c))
  of nkBytes: plain = n.bytes
  else: return n
  var cipher = newSeq[uint8](plain.len)
  for i in 0 ..< plain.len:
    cipher[i] = plain[i] xor key[i mod key.len]     # stand-in for AEAD
  var s = new(Sealed)
  s[] = Sealed(algo: 1'u16, keyRef: keyRef, nonce: @[1'u8, 2, 3],
    tag: @[0xAA'u8], cipher: cipher)
  result = Node(role: n.role, nameId: n.nameId, kind: nkSealed, sealed: s)

proc applyPolicy*(N: var seq[Node], t: NameTable, P: seq[FieldPolicy],
    key: ByteSeq, keyRef: KeyId) =
  ## One pass. No model type ever gains an "Encrypted..." variant.
  for i in 0 ..< N.len:
    if P.sealsField(t.name(N[i].nameId)):
      N[i] = sealed1(N[i], key, keyRef)
