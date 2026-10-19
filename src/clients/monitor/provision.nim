## Provision <- device identities and a shared key through Geist's key API.
import std/[os, strutils, sysrand]
import runePragmas
import geist/network
import geist/[keyfolder, secret]

proc checked*(r: tuple[ok: bool, err: string]) {.role: sanitizer.} =
  ## r: stop immediately when a public Geist operation failed.
  if not r.ok:
    raise newException(IOError, r.err)

proc devicePassword*(root: string): string {.role: dataFetcher.} =
  ## root: private application folder; password stays on this device.
  var
    path: string = root / "password"
  if not fileExists(path):
    raise newException(IOError, "device has not been provisioned")
  result = readFile(path).strip()

proc deviceKeys*(root: string): KeyFolder {.role: configurator.} =
  ## root: sealed key folder and its local unlock credential.
  result = openKeyFolder(root / "keys", devicePassword(root))

proc provisionDevice*(root, subject: string) {.role: orchestrator.} =
  ## root/subject: create an independent signing identity on this device.
  var
    K: KeyFolder = default(KeyFolder)
    path: string = root / "password"
    random: array[32, byte] = default(array[32, byte])
  createDir(root)
  when defined(posix):
    setFilePermissions(root, {fpUserRead, fpUserWrite, fpUserExec})
  if not fileExists(path):
    if not urandom(random):
      raise newException(IOError, "operating system random source failed")
    writeFile(path, toHex(cast[string](@random)))
    when defined(posix):
      setFilePermissions(path, {fpUserRead, fpUserWrite})
  K = deviceKeys(root)
  if not fileExists(K.keyFile(subject, kfPairSecret)):
    checked(K.newPair(subject))
  createDir(root / "peers")

proc deviceIdentity*(root, subject: string): AmeIdentityKey {.role: dataFetcher.} =
  ## root/subject: load this device's own sealed signing keys.
  var
    K: KeyFolder = deviceKeys(root)
    loaded = loadIdentity(K.keyFile(subject, kfPairSecret), K.password)
  if not loaded.ok:
    raise newException(IOError, loaded.err)
  result = loaded.key

proc deviceSharedKey*(root: string): GeistSharedKey {.role: dataFetcher.} =
  ## root: the provisioned group secret; absence is fatal, never pin-only.
  var
    K: KeyFolder = deviceKeys(root)
    got = K.symmetricKey("devices")
  if not got.ok:
    raise newException(IOError, got.err)
  result = initGeistSharedKey("geist-device-monitor-v1", got.value.use())

proc exportSharedKey*(root, path: string) {.role: orchestrator.} =
  ## root/path: generate once with Geist and export for local provisioning.
  var
    K: KeyFolder = deviceKeys(root)
    found = K.findKey("devices")
    words: tuple[ok: bool, words: string, err: string] = (false, "", "")
  if not found.ok:
    checked(K.newSymmetric("devices"))
    found = K.findKey("devices")
  words = K.secretWords(found.entry)
  checked((words.ok, words.err))
  writeFile(path, words.words)
  when defined(posix):
    setFilePermissions(path, {fpUserRead, fpUserWrite})

proc importSharedKey*(root, path: string) {.role: orchestrator.} =
  ## root/path: import the pre-shared secret into this device's sealed keys.
  var
    K: KeyFolder = deviceKeys(root)
    found = K.findKey("devices")
  if found.ok:
    raise newException(ValueError, "device shared key already exists; refusing to replace it")
  checked(K.importWords("devices", kkSymmetric, readFile(path).strip()))
