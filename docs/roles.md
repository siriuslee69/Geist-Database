# What Geist Is For, and the Call for Each Job

Six jobs another program can hand to Geist, one call or one command each,
and where each stops. Every row names a runnable example.

╭⟢ 1. The six roles 🌊
├⟢ 2. The servers it is meant to sit under 🐦‍🔥
╰⟢ 3. Where it stops today 🍣

## 1. The six roles

```text
  role                     import          the calls                   example
  -----------------------  --------------  --------------------------  ---------------------
  write to disk            geist           openGeist, put, set,        geist_quickstart
                                           delete, save
  read from disk           geist           byId, find, list, seek*;    geist_quickstart,
                                           observeStore/followStore    geist_observe,
                                           for a store you do not own  geist_fast_search
  sync, as code            geist/network   needLocal / offerLocal      geist_sync
                                           (same process), needRemote
                                           / offerRemote (a link),
                                           needVia / offerVia (routed)
  background sync daemon   geist/network   serveStore (answer), tick   geist_sync;
                           or geistd       (ask) -- or geistd with     `geistd --help`
                                           --trust / --allow-write
                                           and/or --pull/--push/--sync
  convert data             geist           convertDoc, convertFile,    geist_convert;
                                           toDocText, fromDocText      `geist convert`
  encrypt in memory        geist           sealObject / openObject,    geist_seal
                                           sealWithKey / openWithKey,
                                           ...WithPassword
```

**Def. 1 (pull and push).** To PULL is to ask another store for what this
one lacks (`need`); to PUSH is to send another store what IT lacks
(`offer`). Both remember how far they got, per peer, in a small file beside
the store, so each call moves only what is new -- after a restart too.

**Def. 2 (a node).** A program running `serveStore` is a node others can
reach; a program running `tick` is a node that reaches others. `geistd` is
both, switched on by its options:

```text
  geistd --path mail --identity me.id \
         --allow-write laptop.pin \                   <- others dial in
         --sync vps.pin@dac://vps.example:47655 \     <- this dials out
         --sync-every 30
```

The same two calls fit inside a program's own loop, for a server that
wants to BE the node rather than run one beside it:

```nim
while running:
  discard serveStore(db, cursors, server, 50)   # peers read and write here
  for r in db.tick(agent): log(r)               # every N s, visit peers
  ...                                           # the program's own work
```

## 2. The servers it is meant to sit under

```text
  server            what Geist holds                  start from         fits?
  ----------------  --------------------------------  -----------------  -----------------
  email             one store per mailbox, chosen by  cloud-sync preset; yes; attachments
                    address (registry.nim); phones    registry; geistd   <= ~78 MB each
                    push with offerVia                --sync on replicas (ceiling 4)
  game              player records and world state;   app / live         yes; state sync
                    positions between servers          presets; tick     on a LAN at
                                                                         tens of Hz
                                                                         (ceiling 5)
  cloud             user files' metadata and small    cloud-sync / host  yes for records
                    files; replicas via --sync        presets            and small files;
                                                                         not multi-GB
  password manager  vault entries, sealed per entry   secure-app preset, yes
                    (sealObject) or a sealed store;   sealObject,
                    keys in the OS keystore           keystore
  media stream      the catalogue, playlists,         app preset         metadata yes;
                    positions, who watched what                          the stream itself
                                                                         no (section 3)
```

## 3. Where it stops today

The ceilings are measured in `docs/workloads.md`. The three that decide
the planned servers:

```text
  #  ceiling                              hits
  -  -----------------------------------  ---------------------------------
  4  one transfer is at most ~78 MB       email attachments, cloud files
  5  one update per round trip per link   game positions across continents
  6  a big value is held WHOLE in RAM     cloud files, media
  7  a save rewrites the whole store      very large single stores; keep a
                                          store per mailbox, per player,
                                          per vault instead
```

Video and audio streams do not fit and are not meant to: a stream must
not wait for an acknowledgement per frame, and this transport waits for
one per message. Carry the stream on a transport built for it and keep
what describes it in Geist. `geist-relayd` (docs/relay.md) moves short
clips and messages -- a voice note to a transcriber -- not a film.

What would lift 4, 5 and 6 is listed, in order of value, in
`docs/workloads.md` section 5.
