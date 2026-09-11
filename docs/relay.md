# The relay: Geist with no database

`geistd` serves a database over a pinned, post-quantum transport.
`geist-relayd` is the same daemon with a **pipe** where the store would
be. Same handshake, same `.pin` files, same `Query`/`Reply` wire — a
different handler, and nothing on disk.

It exists because half the things worth doing with an authenticated link
between two of your own machines have no rows in them:

- a phone sends a voice clip to a desktop, which transcribes it and
  answers with the text
- an orchestrator triggers a job on another machine and gets its output
- a script fans log lines at one collector, which appends them as JSON
- a program on a laptop leaves a message for a desktop to collect later

None of those want a packed-row store, a write lease, or a generation
swap, and with `import geist/wire` none of them compile one:

| binary | Geist modules compiled |
|---|---|
| `geistd` | 30 |
| `geist-relayd` | **14** |

The sixteen that are missing are the database — `session`, `store`, `row`,
`rowid`, `keys`, `lease`, `backup`, `sidecar`, `durable`, `mapper`,
`config`, `settings`, `dynamic`, `answer`, `network`, and the batch and
column crypto. Not dead-stripped: never reached. `nimble checkRelay`
compiles a relay and fails if any of them turns up in the C the compiler
emitted.

---

## The shape of it

```
              phone                       desktop
              -----                       -------
   arecord ---> geist-relay send ~~~~~~~~> geist-relayd --to exec
                                                |  bytes on stdin
                                                v
                                           whisper-cpp -
                                                |  transcript on stdout
   transcript <------------------------------ reply
```

One command on each side:

```sh
# desktop
geist-relayd --listen dac://0.0.0.0:47656 \
             --identity /var/lib/geist-relay/pc.id \
             --allow-write peers/phone.pin \
             --to exec --exec 'whisper-cpp -'

# phone
arecord -f S16_LE -r 16000 -d 5 | \
  geist-relay send --remote dac://desktop:47656 --stream voice \
                   --identity phone.id --peer-pin pc.pin
```

The transcript is printed by the same command that sent the audio,
because the relay's reply carries what the command wrote to stdout.

---

## Where a message goes

| `--to` | what happens | reply carries |
|---|---|---|
| `spool` | held in memory for a peer to collect with `geist-relay poll` | nothing |
| `stdout` | written to the daemon's own stdout, for a shell pipeline | nothing |
| `file` | appended to `--file`, one record per message | nothing |
| `exec` | handed to `--exec` on **stdin**; env carries the rest | that command's stdout |

The spool is fed **whatever the sink is**, so a relay piping to a
transcriber can still be polled by a second reader. `--spool 0` turns
that off.

### `--format`, for the `stdout` and `file` sinks

| format | one message looks like |
|---|---|
| `lines` | `2026-08-08T12:04:11Z phone voice a note worth keeping` |
| `json` | `{"at":"2026-08-08T12:04:11Z","from":"phone","stream":"voice","ordinal":3,"bytes":20,"body":"a note worth keeping"}` |
| `raw` | `a note worth keeping` — the bytes, nothing added |

`lines` escapes control characters (`\n`, `\t`, `\xNN`) so one message is
always one line. `json` puts a body that is valid UTF-8 with no NUL under
`"body"` and anything else under `"base64"`: JSON has no way to hold
arbitrary bytes, and escaping them away would silently change the message.
`raw` adds nothing at all, not even a separator — it is for carrying bytes
onward to another program, and a byte the relay invented would corrupt
them.

Both sinks are flushed per message. A log that is the only record of what
arrived is worth a syscall.

### `--to stdout` and the daemon's own chatter

**Every status line goes to stderr** — the banner, the per-request line,
the errors. `--to stdout` is meant to be piped, and a daemon that wrote
`served request 3` into that pipe would corrupt the thing it exists to
deliver:

```sh
geist-relayd --to stdout --format raw ... | ffmpeg -i - -f wav out.wav
```

---

## Running a command per message

```sh
--to exec --exec 'whisper-cpp -' --exec-timeout-ms 60000
```

The command string is the operator's, evaluated by a shell. **The message
is not**: it goes to stdin and nowhere else, so nothing a peer sends can
become a command. A relay that interpolated a message into a shell command
would be handing every pinned peer a shell.

What the command is told, in its environment:

| variable | value |
|---|---|
| `GEIST_STREAM` | the stream the message arrived on |
| `GEIST_FROM` | the sender's subject, from the pin the handshake verified |
| `GEIST_AT` | when this relay accepted it, ISO-8601 UTC |
| `GEIST_BYTES` | how many bytes are on stdin |

`--exec-timeout-ms` (default 30 000, because transcription is not quick)
stops a command that overstays, so one wedged transcriber cannot wedge the
daemon forever. `--exec-timeout-ms 0` starts the command and does **not**
wait for it — the fire-and-forget trigger — and the handle is reaped on a
later request rather than left as a zombie.

Two limits worth knowing:

- **Requests are handled one at a time.** While a command runs, that relay
  serves nobody else. For a personal orchestrator that is the right
  trade; for a shared one, run a relay per stream on its own port.
- **The command's stdout must fit the pipe buffer** (64 KiB on Linux), or
  it blocks until the timeout. A command with more than that to say should
  write it somewhere and answer with the path.

---

## Collecting instead of piping

A relay in the middle holds a message until the other side asks:

```sh
# desktop, holding messages for whoever asks
geist-relayd --to spool --spool 512 --trust peers/laptop.pin ...

# laptop, later
geist-relay poll --remote dac://desktop:47656 --stream notes \
                 --as laptop --format json --follow
```

Each reader name has its own position, so two readers of one stream each
see everything once rather than racing for it. A name that has never been
seen starts at zero and gets what is still held — which is bounded by the
spool, so there is no need to make a reader say hello before it may ask.

**The spool is a bounded ring in memory.** When it is full the *oldest*
message is dropped and counted; a relay that shed the newest would go
quiet exactly when it got busy. A reader can tell it missed some: every
answer carries the total the stream has ever accepted, so a cursor that
moved further than the messages handed over is a gap. Nothing survives a
restart. **A message that must survive one wants `geistd`.**

---

## Who may do what

The same rule as the database daemon, because it is the same pin:

| flag | may send | may collect |
|---|:--:|:--:|
| `--trust <pin>` | no | yes |
| `--allow-write <pin>` | yes | yes |

Pins are exchanged out of band, and that exchange **is** the trust
decision:

```sh
geist-relayd --identity pc.id --subject pc --pin-out pc.pin     # on the relay
geist-relay pin --identity phone.id --subject phone --pin-out phone.pin
```

Who sent a message is `p.subject` — the name on the certificate the
handshake verified, not anything the payload said. It is the one fact a
relay can vouch for, so it is the one field it stamps on the envelope a
collector receives.

`--stream <name>` (repeatable) narrows what may arrive at all. Worth
setting when the sink is a command: it stops a peer inventing a stream
nobody configured.

---

## It is not a database, and says so

```
$ geist --remote dac://desktop:47656 --identity me.id --peer-pin pc.pin list
geist: this endpoint is a relay, not a database: it forwards messages and
keeps 256 per stream in memory. Point qoFind at a geistd instead.
```

Answering "no rows" to a program that thought it was querying a store
would be a lie that costs an afternoon.

---

## On NixOS

```nix
services.geist-relay = {
  enable = true;
  listenHost = "192.168.50.10";
  openFirewall = true;
  identityFile = "/var/lib/geist-relay/relay.id";
  identityPasswordFile = config.age.secrets.relay-id.path;
  allowWrite = [ ./peers/phone.pin ];    # may SEND
  trust = [ ./peers/laptop.pin ];        # may COLLECT
  streams = [ "voice" ];
  to = "exec";
  exec = "${pkgs.whisper-cpp}/bin/whisper-cpp -";
  execTimeoutMs = 60000;
};
```

Its own module (`nix/relay-module.nix`, exported as
`nixosModules.geist-relay`), because a machine that only moves messages
has no database options to answer for. Pins are plain paths — a pin is the
half of an identity you are meant to hand out; the identity password goes
through `LoadCredential` so it is never copied into the store.

The unit is sandboxed (`ProtectSystem=strict`, `ProtectHome`,
`PrivateDevices`, `NoNewPrivileges`, …) and **that sandbox applies to the
command `exec` runs too**, which is deliberate. `readWritePaths` widens it
when a command needs somewhere else to write.

`services.geistd` and `services.geist-relay` coexist on one machine: the
relay's default port is 47656, one above the daemon's.

---

## Config file

```toml
[relay]
listen = "dac://0.0.0.0:47656"
identity = "/var/lib/geist-relay/relay.id"
identityPasswordFile = "/run/secrets/relay-id"
allowWrite = ["peers/phone.pin"]
to = "exec"
exec = "whisper-cpp -"
execTimeoutMs = 60000
stream = ["voice"]
spool = 256

[relayClient]
remote = "dac://192.168.50.10:47656"
peerPin = "peers/pc.pin"
identity = "phone.id"
stream = "voice"
```

Read from `userconfig.toml` in the working directory, then
`~/.config/geist/userconfig.toml`. **A typed flag always beats the file**,
and an unknown key in either section is an error rather than a shrug — a
misspelled setting that is silently ignored looks exactly like one that
took effect.

---

## What proves it works

| check | what it covers |
|---|---|
| `nimble test` (`evaluation/tests/test_relay.nim`) | envelope round-trip, spool eviction and its count, per-reader cursors, rights, both log formats, exec on stdin, exec timeout, fire-and-forget |
| `nimble checkRelay` | compiles a relay and asserts **no database module was emitted** — the modularity claim, checked rather than asserted |
| `nix build .#checks.x86_64-linux.relay-pipe -L` | three real NixOS guests: a phone sends, a desktop transcribes and answers, a laptop collects from the spool, a JSON log holds binary as base64, and a database client is told this is not a database |
