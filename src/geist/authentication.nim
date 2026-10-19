## Shared authentication <- Geist's PSK plus the existing pinned signatures.
## A configured shared key always selects AM1P+S; it never retries AM1S.
import bifrost_exchange_protocols as bfx
import runePragmas
import ./secret

type
  GeistSharedKey* {.role: configurator.} = ref object
    identifier*: string
    secret: Secret

proc initGeistSharedKey*(identifier: string,
    K: openArray[uint8]): GeistSharedKey {.role: configurator.} =
  ## identifier/K: provisioned name and at least 32 random secret bytes.
  if identifier.len == 0 or K.len < 32:
    raise newException(ValueError, "Geist shared authentication needs a name and at least 32 key bytes")
  result = GeistSharedKey(identifier: identifier, secret: initSecret(K))

proc enabled*(k: GeistSharedKey): bool {.role: parser, inline.} =
  ## k: whether AM1P+S was explicitly provisioned.
  result = k != nil and k.identifier.len > 0

proc `$`*(k: GeistSharedKey): string {.role: helper.} =
  ## k: logs may name the mode, never the secret.
  result = if k.enabled(): "GeistSharedKey(AM1P+S)" else: "GeistSharedKey(none)"

proc authenticationFor*(k: GeistSharedKey,
    p: bfx.AmePinnedPeerIdentity): bfx.AmeAuthentication {.role: configurator.} =
  ## k/p: both factors when a PSK is configured, otherwise pin authentication.
  if k.enabled():
    return bfx.initAmePskPinnedAuthentication(k.identifier, k.secret.use(), p)
  when bfx.atmPinnedPeerKey in bfx.ameModesBuilt:
    result = bfx.initAmePinnedAuthentication(p)
  else:
    raise newException(ValueError, "this Geist build requires AM1P+S; no shared key was configured")

proc authenticationName*(k: GeistSharedKey): string {.role: parser.} =
  ## k: public mode label, safe for event logs.
  result = if k.enabled(): "AM1P+S" else: "AM1S"
