# Geist on NixOS

Four things live under `nix/`:

| file | what it is |
|---|---|
| `default.nix` | the package: the daemons and their clients |
| `module.nix` | `services.geistd` and `programs.geist-client` |
| `relay-module.nix` | `services.geist-relay`, the daemon with no database |
| `nix/tests/` | three NixOS VM tests that run real machines against each other |

## The package

`default.nix` builds four binaries with the same flags the nimble tasks
use (`-d:release --mm:orc --threads:on`), because a package built under a
different memory model from the one the test suite runs under is a package
nothing has actually tested:

- `geistd` from `src/server/geistd.nim`
- `geist` from `src/clients/geist_cli.nim`
- `geist-relayd` from `src/server/geist_relayd.nim`
- `geist-relay` from `src/clients/geist_relay.nim`

The relay pair is the same transport with a pipe where the store would be,
and it is its own module because a machine that only moves messages has no
database options to answer for. See [relay.md](relay.md).

All four are wrapped with `LIBSODIUM_LIB_DIRS` and the library path for
libsodium, and nothing else — Geist has no TPM or libsecret backend.

Every direct dependency defaults to `../submodules/<name>`, the checkout
this repo pins. Override the `*Src` arguments only for a deliberate local
experiment: pointing a build at a sibling workspace checkout hides
submodule drift and can reproduce a different API graph than the repo you
have.

## `services.geistd`

```nix
services.geistd = {
  enable = true;
  path = "/var/lib/geist/notes";        # a store root DIRECTORY
  listenHost = "192.168.50.10";
  openFirewall = true;
  identityFile = "/var/lib/geist/geistd.id";
  trust = [ "/var/lib/geist/peers/laptop.pin" ];        # may read
  allowWrite = [ "/var/lib/geist/peers/desktop.pin" ];  # may also write
};
```

The command line is assembled from the options, so every option maps to
exactly one flag of the daemon that exists:

| option | flag |
|---|---|
| `path` | `--path` |
| `preset` | `--preset` |
| `listenHost`, `listenPort` | `--listen dac://host:port` |
| `subject` | `--subject` |
| `identityFile` | `--identity` |
| `passwordFile` | `--password-file`, via a systemd credential |
| `identityPasswordFile` | `--identity-password-file`, via a credential |
| `trust` | one `--trust` per pin |
| `allowWrite` | one `--allow-write` per pin |
| `timeoutMs`, `idleSeconds`, `maxRequests`, `quiet` | the same names |
| `settings` / `configFile` | `--config`, a generated `userconfig.toml` |

### Rights come from the option, not from the request

`trust` grants reads. `allowWrite` grants reads **and** the right to send
rows. A peer cannot ask for more than the pin it handshook with was
listed under.

That choice has a consequence worth planning around: **`allowWrite` makes
the daemon take the store's write lease**, because serving a write means
being the writer, and there is one writer per store root. While such a
daemon runs, a direct `geist put` on the same store is refused by name.
A `trust`-only daemon takes no lease, so the desktop's own CLI keeps
working — and the daemon notices the file moved underneath it and reloads,
at a cost of one index read.

So a node that has to apply what it receives (any node catching up with
`geist sync`) should be `trust`-only. A node that is written to *across
the wire* is the one that wants `allowWrite`.

### Secrets and pins are handled differently, on purpose

**Pins are public.** They are the half of an identity you are meant to
hand out, so `trust` and `allowWrite` take plain paths — either store
paths (`./peers/laptop.pin`) or runtime paths for pins that arrive by
other means.

**Passwords are not.** `passwordFile` and `identityPasswordFile` are
loaded through systemd credentials, so they are never copied into the
world-readable Nix store and are readable only by the service.

### The identity file must persist

`identityFile` defaults to `/var/lib/geist/geistd.id` and is created on
first start. It cannot be a store path, and the module asserts as much: a
daemon that minted a fresh key on every start could never be pinned by
anybody, which makes it unusable as a peer.

To publish the public half before starting the service — which you must,
since a daemon refuses to start until the peer it trusts has a pin on
disk:

```console
$ geistd --path /var/lib/geist/notes \
         --identity /var/lib/geist/geistd.id \
         --identity-password-file /run/geist-secrets/id.pw \
         --subject desktop-a \
         --pin-out /var/lib/geist/desktop-a.pin
```

That writes the pin and exits without opening the database. Hand the file
to the other desktop by any means you like; **that exchange is the trust
decision**, and nothing in Geist makes it for you.

### Bootstrapping order

1. `geistd --pin-out` on each machine.
2. Copy each pin to the machines that should trust it.
3. Name those paths in `trust` / `allowWrite`.
4. Start the service.

Because of step 3, a first deployment usually sets
`systemd.services.geistd.wantedBy = lib.mkForce [ ]`, does 1 and 2, then
starts the unit by hand. Both VM tests do exactly this.

### Hardening

The unit runs as the `geist` system user with `ProtectSystem=strict` and
`ReadWritePaths = [ stateDir ]`, no device access, a `@system-service`
syscall filter and `MemoryDenyWriteExecute`. The daemon reads and writes
one directory and speaks UDP; it needs nothing else.

## `programs.geist-client`

Installs the CLI and generates `userconfig.toml` files:

```nix
programs.geist-client = {
  enable = true;
  settings = {
    database.path = "/var/lib/geist/notes";
    client = {
      remote = "dac://192.168.50.10:47655";
      peerPin = "/var/lib/geist/peers/desktop-a.pin";
    };
  };
};
```

Note where the CLI looks: the **working directory** first, then
`~/.config/geist/userconfig.toml`. It does not read `/etc`. So reach the
generated file explicitly:

```console
$ geist --config /etc/geist/userconfig.toml list
```

…or symlink it into a user's config directory. Keys are validated on load
— an unrecognised one is an error rather than a silently ignored line,
which is what makes generating this file worth doing at all.

`profiles` generates additional named configs below `/etc`, each of which
either merges into the global `settings` or replaces them.

## `services.geist-relay`

A separate module in `nix/relay-module.nix`, exported as
`nixosModules.geist-relay`, for the daemon that moves messages and stores
nothing. It shares this one's trust model exactly — `trust` may collect,
`allowWrite` may send, pins are plain paths, the identity password goes
through a credential, and the identity file must persist — and adds only
the question of where a message goes: `to`, `format`, `file`, `exec`,
`streams`, `spool`.

Its default port is 47656, one above `geistd`'s, so a machine can run both
without either being told about the other. Full options and the reasoning
in [relay.md](relay.md).

## The VM tests

```console
$ nix build .#checks.x86_64-linux.two-desktop-exchange -L
$ nix build .#checks.x86_64-linux.three-desktop-relay -L
$ nix build .#checks.x86_64-linux.relay-pipe -L
```

All three boot real NixOS guests on a real network and drive the real
binaries. They need KVM.

**`two-desktop-exchange`** runs two desktops configured deliberately
*differently* — `alpha` encrypted (`secure-app`) and writable by its peer,
`beta` plain and read-only — so each half of every choice gets exercised:
a peer under `allowWrite` writes across the wire and a peer under `trust`
is refused and told why; the writable daemon's lease blocks a local write
while the read-only one does not; an acknowledged remote write is on disk
rather than in RAM; the encrypted store has no plaintext in it and the
plain one does; and the module's generated `userconfig.toml` is one the
CLI actually accepts.

**`three-desktop-relay`** chains three databases: `origin → middle → tail`.
It has nothing to do with `services.geist-relay` — the name predates it
and describes a chain of daemons, not a message pipe. The two
ends share a network but hold no pin for each other, and the test checks
both facts, so nothing it observes can be explained by the ends talking
directly.

The point of the third machine is that **`middle` is not a relay
component**. There is no forwarding code and no relay mode: it follows
`origin` with the same `geist sync` call `tail` uses to follow it, and
serves what it has with the same daemon `origin` runs. What the test
actually pins down is that a row arrives at `tail` under the id `origin`
minted for it, two hops away. A chain that re-minted ids at each hop would
still *look* correct — rows would arrive, counts would match — and would
diverge silently the first time `origin` updated a row, because the update
would land beside its target instead of on it. So the test compares ids
across the chain, then makes `origin` update one row and delete another
and checks that both ends converge.

**`relay-pipe`** has no database in it at all. A `phone`, a `pc` running
`services.geist-relay` with `to = "exec"`, and a `laptop` that only
collects. The phone sends bytes; a program on the pc reads them from stdin
and its stdout comes back as the reply; the laptop polls the same message
out of the spool without consuming the phone's.

Along the way it checks the things only a real machine can show: that the
sender's name on the far side is the one the *handshake* proved rather
than anything the payload said, that a peer under `trust` alone is refused
when it tries to send, that a stream nobody configured is refused by name,
that a JSON log holds text as text and a NUL-bearing body as base64, that
pointing the `geist` CLI at it produces "this endpoint is a relay, not a
database" rather than an empty list — and that the relay's state directory
holds keys and a log and no store at all.
