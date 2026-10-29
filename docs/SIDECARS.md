# Sidecars <- big values kept beside the row

A row is a fixed box. A long text does not fit a box well, so Geist moves the
long value into a small file of its own, and the row keeps a short reference.
This page explains that, where the files go, how to track files you already
have, how the folder is protected, and how a file can live on another machine.

```
  ROW (fixed size)                    SIDECAR FILE (the long value)
  +------+---------+------------+     +------------------------------+
  | id   | title   | reference  | --> | .geist-sidecar/ab/cd/abcd... |
  +------+---------+------------+     +------------------------------+
     small          33 bytes             the value, named by its hash
```

## 1. Definitions

```
Def. 1 (sidecar)      a file named by the hash of its own bytes.
                      Same bytes, same name: identical values are kept once.

Def. 2 (threshold)   a value at or above [default] sidecarThreshold (1 KiB)
                      moves out of its row, when sidecars are on. A capped
                      column also moves a value that is too wide for it.
                      A fixed-width column never moves a value.

Def. 3 (storage path) a folder in [default] storage. The store puts ONE
                      folder inside it, named  <store>-<12 hex>.geist-sidecar,
                      where the hex is the hash of the store's full path.
                      Two stores never share that folder.

Def. 4 (locator)      a small text file  <hash>.locator  that stands in for a
                      payload kept elsewhere: a tracked file (kind "path") or a
                      payload on another machine (kind "remote").

Def. 5 (sweep)        deletes every payload that no live row and no backup
                      slot names. Refused when the folder holds more than one
                      database, because they would delete each other's files.

Def. 6 (fail closed)  when a check cannot be made, Geist refuses. See section 5.
```

## 2. Where the files go

```
  store folder  data/notes/
  |-- main.ge1st.g2          the rows
  |-- main.params            settings the bytes depend on
  |-- geist.version          format, digest
  |-- geist.permissions      read / write / sidecars, digest
  |-- .geist-sidecar/        the fallback folder, always last
  |     ab/cd/abcd...        a payload
  |     ab/cd/abef...locator a locator (tracked or remote)
  |
  storage path  /mnt/fast/                       (from [default] storage)
  |-- notes-3fa19c02d7e1.geist-sidecar/          one folder per store
        ab/cd/abcd...                            a payload
```

The fallback folder is used when no storage path has room, or when none is
listed. Payloads written before storage paths existed stay readable there.

## 3. Storage paths and speed

```
  for a new payload, the store walks its roots in order:

  root (storage path + store folder)
    |-- folder missing?  -> skipped (an unplugged drive is never written)
    |-- free space known and too small? -> skipped
    '-- otherwise a candidate

  policy priority  the first candidate in the list is used
  policy speed     the fastest candidate is used; a folder never measured
                   counts as slowest; ties keep the list order
```

Speeds are measured by a command, and kept inside the storage path in a file
named `.geist-speed`. The drive keeps its speed wherever it is mounted. A run
reads that file once.

```
  geist storage list                    drives found, free space, speed
  geist storage bench <folder> --mb 16  measure and record the speed
```

## 4. Tracking a file you already have

`track` makes a row that refers to a file where it lies. Geist reads the file
and never writes it. The row keeps the file's hash, so a read checks that the
file has not changed.

```
  geist --path db track ~/Documents --suffix .txt
           |
           |  one row per file:  name | path | size | file (reference)
           v
  reading the row: hash the file again
     same hash  -> the value
     changed    -> refused, and the reason says so
     missing    -> refused, and the path is named
```

The database needs the columns `name:text,path:text,size:int,file:ref`.
Create one with `init --schema "name:text,path:text,size:int,file:ref"`.

## 5. The folder files (fail closed)

Every database folder carries two small files, and each ends with a digest
(BLAKE3 of the lines above it).

```
  geist.version      format = 4, created, digest
  geist.permissions  read = allow, write = allow, sidecars = allow, digest
  <name>.params      hash families, cipher, batch size, digest

  check:
    files missing or not parsing   -> refused for reading AND writing
    digest does not match          -> refused for reading AND writing
    write = deny                   -> read only
```

`geist folder show <dir>` prints the files and every database's rows, as text
or with `--json`. It makes no check and writes nothing. It is for a person who
needs to see what is there.

`geist folder adopt <dir>` gives a folder without files its two files. It is
refused when the folder already has files, so it can never replace a check.

## 6. Remote payloads

A payload can be kept by another machine. The local folder then holds a
locator of kind `remote`, with the holder's address, the holder's name, the
name of the machine that signed the locator, and the signature.

```
  Geist finds only a locator
     |
     v
  hook (installed by nebel)  --> fetch from the holder
     |
     v
  Geist checks the bytes against the row's hash, whatever came back
```

Geist does not talk to the network. The fetch is a hook that a program
installs. Without the hook, a remote payload is named in the error, not read.
Nebel's page `Nebel docs/remote_sidecars.md` describes the sending side.

## 7. Settings

```
  [default] (may change while the program runs)
    sidecarThreshold = 1024      bytes at or above which a value moves
    sidecars = true              off: nothing new leaves its row
    follow = "named"             how search reads a sidecar value
    storage = []                 storage paths, preferred first
    storagePolicy = "priority"   or "speed"

  [define] (compile time, changes need a new build)
    sidecars = true              off: the build refuses to write or read a
                                 sidecar; inline values work as before
```

Run-time overrides for one command: `--sidecars on|off`, `--storage a,b`,
`--storage-policy priority|speed`.

## 8. Commands

```
  track <file|folder>        reference files in place (--top, --suffix)
  folder show <dir>          force read (--json)
  folder adopt <dir>         give a bare folder its two files
  storage list               drives, free space, recorded speeds
  storage bench <dir>        measure and record a speed (--mb)
  sweep                      delete payloads nothing names
```

## 9. Rows that leave for a peer

A row sent to a peer must be readable by the peer on its own. So a long text
that sits in a sidecar is written back into the row before it leaves.

```
  stored row                     row on the wire
  +----+------+-------+          +----+--------------------------+-------+
  | id | body | (ref) |  --->    | id | body: the whole text      | ref   |
  +----+------+-------+          +----+--------------------------+-------+
                                  body is variable: written back
                                  ref stays a reference: it names a local file
```

| column kind        | on the wire                                        |
|--------------------|----------------------------------------------------|
| variable (text, bytes) | written back whole                             |
| capped             | stays a reference: its width is fixed, and a value wider than the column cannot fit |
| reference (`ref`) | stays a reference: it names a payload where it lies |
| number, fixed      | as stored                                          |

Nebel applies this to every reply that carries rows (`nebel/answer.nim`), and
a reply that carries whole values is kept inside one frame when it can be.

## 10. Limits and edge cases

```
  moving a store folder     its payloads in storage paths stay where they are;
                            the new path has new folder names, so reads of
                            those payloads fail, loudly. Move the storage
                            folders with the store, or copy them back.

  two databases, one folder  sweep is refused: they share the fallback folder.

  sidecars off               a capped value that does not fit follows the
                            column's overflow rule (cut and counted, or refused)
                            instead of moving out.

  a reference with no value  a `ref` cell that is empty reads as a sidecar
                            reference to an all-zero hash. The stored format
                            cannot tell "no reference" apart yet; a format
                            change would be needed.
```
