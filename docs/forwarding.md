# Through a VPS: Client -> VPS -> Home

A home server has no address the world can reach. A rented machine (a VPS)
has one. Geist has two ways to use the second to reach the first, and they
are not interchangeable.

╭⟢ 1. The two ways 🌊
├⟢ 2. Forwarding: one handshake, made end to end 🐦‍🔥
├⟢ 3. Running it 🍣
├⟢ 4. What the forwarder checks, and what it cannot 🌿
╰⟢ 5. Edge cases ⌜guide⌟

## 1. The two ways

```text
  A. FORWARD (geist-forwardd)              B. MAILBOX (geistd on the VPS)

  client ----> VPS ----> home              client ----> VPS <---- home
          bytes    bytes                            asks      dials OUT
          untouched                                and gets  and pushes
                                                   a copy
  ONE handshake: client <-> home           TWO handshakes: client <-> VPS,
                                           home <-> VPS. Each is its own.
  home must be reachable FROM the VPS      home only needs to reach OUT
  (VPN, forwarded port, public IPv6)       (works behind any router)
  answers come from home, live             answers come from the VPS's copy,
                                           as fresh as the last sync
  VPS holds no key, reads nothing          VPS holds the data (and its key)
```

Pick A when home can be reached from the VPS and the answer must be live.
Pick B when home is behind a router that lets nothing in, or when the copy
on the VPS is wanted anyway (a phone that reads while home is off).

`geist-routed` (docs/federation.md) is a third thing: a router that OPENS
each request, decides where it goes and narrows the caller's rights. It
makes its own handshake to the next hop, so a link through it costs two
handshakes. Use it when the VPS must decide; use A when it must not.

## 2. Forwarding: one handshake, made end to end

**Def. 1 (forwarder).** A program on the VPS that receives a datagram from
a client and sends the same bytes to home, and the reverse. It has no key
and opens nothing.

**Def. 2 (tag).** The forwarder gives each client one socket of its own
toward home. Home sees a different source port per client. An answer comes
back on that socket, and the socket names the client.

```text
  client A ---> front socket ---> [ tag 1 socket ] ---> home
  client B ---> front socket ---> [ tag 2 socket ] ---> home
  client A <--- front socket <--- [ tag 1 socket ] <--- home
```

Nothing is added to a datagram, so the bytes home reads are the bytes the
client sent. The handshake therefore runs between client and home, and
costs what it costs without a VPS in between:

```text
  measured on one machine, `geist list` through a running geistd:
    direct         0.22 s
    via forwarder  0.22 s
```

The client changes one thing: the address it dials.

```text
  geist --remote dac://vps.example:47655 --peer-pin home.pin ...
                       ^ the VPS            ^ the HOME server's pin
```

## 3. Running it

On the VPS:

```sh
geist-forwardd --listen dac://0.0.0.0:47655 --to dac://10.8.0.2:47655
```

On NixOS:

```nix
services.geist-forward = {
  enable = true;
  openFirewall = true;
  home = "10.8.0.2:47655";
};
```

Home runs its ordinary `geistd`. Every number below has a flag, a line in
`[runtime.forward]` of `configs/default.toml` and a NixOS option:

```text
  setting            default   what it bounds
  -----------------  --------  ------------------------------------------
  maxClients         512       places for clients. Full -> the newcomer is
                               refused; nobody is pushed out
  clientIdleSeconds  120       quiet this long -> the place and its socket
                               are given back
  pingSeconds        20        how often the VPS asks home "still there?"
  silentSeconds      60        silence before home counts as away
  bufferDatagrams    64        held for an away home (the newest)
  bufferBytes        262144    the same limit in bytes
  followHome         false     chase a home address that changed
```

## 4. What the forwarder checks, and what it cannot

With no key it can check only what needs none:

```text
  check                                        if it fails
  -------------------------------------------  ---------------------------
  datagram is 1..65507 bytes                   dropped, counted
  a client place is free                       dropped, counted
  an answer came FROM home's address           dropped, counted "strangers"
  a pong came FROM home (unless followHome)    dropped, counted "strangers"
```

It cannot tell a good handshake from a bad one, so a stranger who reaches
the VPS port reaches home's port, the same as if home were public. Home
still refuses every stranger at the handshake (pins), and its cookie
challenge (`requireCookie`) still stops forged senders from costing it a
key exchange. What the VPS adds is a second place to be flooded; keep
`maxClients` low if the VPS is small.

**The ping.** Every `pingSeconds` the forwarder sends home the 14 bytes
`GEIST-FWD-PING`; a Geist server answers `GEIST-FWD-PONG` at once, before
decoding anything and without touching a session (`src/geist/ping.nim`).
Same length both ways, so a forged source address gains nothing.

## 5. Edge cases

```text
  case                                        what happens
  ------------------------------------------  ----------------------------
  home reboots                                datagrams held, newest 64;
                                              the rest is asked for again
                                              by the transport above
  home is off for minutes                     the held ones are dropped,
                                              oldest first, and counted
  a client idles past clientIdleSeconds       its socket is closed; on
                                              return it gets a NEW one, so
                                              home sees a new source port.
                                              Home drops the old session
                                              when the new hello arrives
  home's address changes                      followHome = true, or restart
                                              the forwarder
  home is a name, not a number                resolved ONCE at start
  home is behind a router with no forward     forwarding cannot work; use
                                              way B
  two forwarders in a row                     works; each is blind
  the client wants to be dialled BY home      not possible through A: the
                                              client is the one who opens
                                              the path. Home pushes to a
                                              geistd on the VPS (way B)
```
