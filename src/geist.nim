## ---------------------------------------------------------------------
## Geist <- the public facade
## ---------------------------------------------------------------------
##
##   import geist
##
##   var db = openGeist[Note]("data/notes", appConfig())
##   db.put(Note(title: "hello"))
##   echo db.find("title", "hello")
##   db.save()
##   db.close()
##
## Encrypted, with change following:
##
##   var db = openGeist[Note]("data/notes", secureAppConfig(), "password")
##   discard db.subscribe("watcher")
##   db.put(Note(title: "later"))
##   for e in db.poll("watcher"): echo e.ordinal, " ", e.cluster
##
## Observing a database this process does NOT own -- reads only the
## header and cluster index, a few hundred bytes regardless of file size:
##
##   var seen = observeStore("data/notes")
##   var now = followStore(seen.f, "data/notes")
##   echo now.changed   # which clusters moved
##
## Name the STORE, not a file: a save publishes a new generation, so the
## live file name changes and `observeStore` re-resolves it every time.
##
## THIS MODULE IS THE STORAGE HALF, and nothing here opens a socket. A
## program that only writes rows to disk compiles only what that needs --
## no handshake, no post-quantum KEM, no peer directory.
##
## Talking to a peer is the other half, and it is one import away:
##
##   import geist
##   import geist/network
##
##   var me = geistIdentity("node-a")
##   var link = connectGeist(remote, me, peerPin, defaultTierPolicy())
##   discard link.link.send(Query(op: qoFind, collection: "notes"))
##
## `geist/network` re-exports this module, so the two lines above can be
## the single line `import geist/network` when a program wants both.
## Splitting them is what keeps an embedded, offline, disk-only build from
## paying for a stack it never calls -- see `docs/nix.md` and the module
## header of `geist/network.nim` for what each half contains.

import std/os

import runePragmas
import ./geist/types
import ./geist/secret
import ./geist/durable
import ./geist/format
import ./geist/lease
import ./geist/mapper
import ./geist/rowid
import ./geist/sidecar
import ./geist/store
import ./geist/row
import ./geist/config
import ./geist/backup
import ./geist/keys
import ./geist/session
import ./geist/crypto/cipher
import ./geist/crypto/mac
import ./geist/crypto/batch
import ./geist/crypto/column
import ./geist/dynamic
import ./geist/show
import ./geist/transpose
import ./geist/toml_read
import ./geist/doc
import ./geist/reconcile
import ./geist/address
import ./geist/route
import ./geist/keystore
import ./geist/secrets
import ./geist/users
import ./geist/layout
import ./geist/settings
import ./geist/collection
import ./geist/seek
import ./geist/crypto/hashing

export types, secret, config, backup, session
export toml_read, settings
export doc, reconcile, address, route, keystore, layout
## The one crypto surface an application needs, so nothing outside Geist
## has to import Tyr to hash a password or unlock a store.
export secrets, users
export mapper
export rowid
export durable
export lease
export sidecar
export store
export row
export format
export keys
export cipher
export mac
export batch
export collection
export seek
export hashing
export column
export dynamic
export show
export transpose

proc openGeist*[T: object](path: string, c: GeistConfig = appConfig(),
    password: string = "", readOnly: bool = false): Session {.
    role: orchestrator,
    tag: "appApi|db|orchestrator|storageIo".} =
  ## path: store root directory, or a `<dir>/<name>` stem. The artifact set
  ##   (data, keys, ledger), the manifest and the sidecar folder all live
  ##   under the directory, so a database is always a self-contained
  ##   directory rather than a loose file.
  ## c: configuration; a named preset or a caller-composed value.
  ## password: required when the configuration selects a cipher.
  ## readOnly: follow the database without claiming the write lease. Check
  ##   `session.readOnly` afterwards either way: a writable open whose lease
  ##   is already held downgrades itself instead of failing.
  var
    dir: string = path
    name: string = "main"
  if path.len > 0 and path.splitFile().ext.len > 0:
    # An explicit extension means the caller named a file, so the store
    # root is its parent. Anything else is a directory, whether or not it
    # exists yet -- guessing from existence would make the same argument
    # mean different things on first and second run.
    dir = path.parentDir()
    name = path.splitFile().name
  result = openSession[T](dir, name, c, password, readOnly)

proc geistVersion*(): string {.role: helper, stage: stDone,
    tag: "appApi|status".} =
  ## The format version this build reads and writes.
  result = "geist format v" & $geistFormatVersion
