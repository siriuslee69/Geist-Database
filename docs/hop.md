# Through a hop router: one link, many machines

╭⟢ 1. What it is, in plain words 🌊
├⟢ 2. Running it 🐦‍🔥
├⟢ 3. The words ✦
├⟢ 4. The config, line by line 🍣
├⟢ 5. Two routers ❧
├⟢ 6. What the router sees, and what it cannot ⌜guide⌟
╰⟢ 7. Edge cases and limits ୨୧

## 1. What it is, in plain words 🌊

A phone wants to read the database on a home NAS. Nobody can dial the NAS
from outside. A small rented machine (a VPS) can be dialled by everyone.

`geist-hopd` runs on the VPS. The NAS dials OUT to it and stays linked.
The phone dials it too. Then the phone opens an ordinary Geist link to
the NAS -- end to end, with the NAS's pin -- and the router hands the
frames on:

```text
  phone ==link==> geist-hopd (VPS) <==link== NAS (geistd --hop)
    |                                          |
    +------ end-to-end Geist link, inside -----+
            phone pins the NAS; the NAS pins the phone
```

Each `==link==>` is one ordinary handshake with the router. The router
holds THOSE keys. The end-to-end link is a second handshake, made between
phone and NAS, whose keys the router never holds. So the router knows who
talks to whom and how much -- never what.

How this differs from the other ways through a VPS (docs/forwarding.md):

```text
                     geist-forwardd       geist-routed          geist-hopd
                     (forwarder)          (request router)      (hop router)
  ----------------   ------------------   -------------------   -------------------
  NAS must be        reachable FROM the   reachable FROM the    able to dial OUT,
                     VPS                  VPS                   nothing more
  VPS reads          nothing              every request         who talks to whom
  handshakes         1 (client <-> NAS)   2 (client <-> VPS,    1 per link + 1 end
                                          VPS <-> NAS)          to end
  many targets       one home             by app name           by route id,
                                                                directory per client
```

## 2. Running it 🐦‍🔥

Exactly the commands of the end-to-end check this was built with (all on
one machine here; on a real VPS replace `127.0.0.1` with its address):

```sh
echo pw > pw

# 1. identities and pins (each side keeps its .id, hands out its .pin)
geist keygen --identity phone.id --pin-out phone.pin --subject phone --password-file pw
geistd --path db --password-file pw --identity nas.id \
       --identity-password-file pw --subject nas --pin-out nas.pin
geist-hopd --identity hop.id --identity-password-file pw --pin-out hop.pin

# 2. the router: who may link, and the directory (section 4)
cat > hop.toml <<'TOML'
listen = "dac://127.0.0.1:47758"
id = 16
identity = "hop.id"
identityPasswordFile = "pw"
[[peer]]
  pin = "phone.pin"
  id = 48
[[peer]]
  pin = "nas.pin"
  id = 32
[[target]]
  id = 32
  name = "nas"
  visibleTo = ["phone"]
TOML
geist-hopd --config hop.toml

# 3. the NAS links to the router and stays linked
geistd --path db --password-file pw --identity nas.id \
       --identity-password-file pw --subject nas \
       --trust phone.pin --hop dac://127.0.0.1:47758 --hop-pin hop.pin
#   -> linked to router dac://127.0.0.1:47758 (geist-hop)

# 4. the phone asks whom it may reach ...
geist routes --hop dac://127.0.0.1:47758 --hop-pin hop.pin \
             --identity phone.id --password-file pw
#   0x0020  nas

# ... and reads the NAS through the router
geist list --hop dac://127.0.0.1:47758 --hop-pin hop.pin --target nas \
           --identity phone.id --peer-pin nas.pin --password-file pw
```

`--peer-pin` names the NAS, not the router: the link runs end to end.
`--target` takes a name from the directory or a route id (`32`, `0x20`).

From code:

```nim
import geist/network

var hop = connectHop(routerAt, myKey, routerPin, defaultTriggerPolicy())
var dir = hop.hop.routeDirectory()              # @[(id: 32, name: "nas")]
var made = connectGeistVia(hop.hop, 32, myKey, nasPin,
  defaultTriggerPolicy())
discard made.link.send(Query(op: qoFind))

# a server reachable through a router:
server.attachHop(connectHop(routerAt, serverKey, routerPin,
  defaultTriggerPolicy()).hop)
while running: discard server.serveAnyOnce(handler)
```

On NixOS: `services.geist-hop` (nix/hop-module.nix) for the router,
`services.geistd.hop` / `hopPin` for a daemon behind it. Build by hand:
`nimble buildServerHopd`. Port: UDP 47658 (docs/ports.md).

## 3. The words ✦

**Def. 1 (link).** One ordinary Geist handshake between a machine and the
router, and the session it opens. Through it go two kinds of frame: AME
frames for the router itself (the directory question) and Bifrost route
frames ("ART") for someone behind it.

**Def. 2 (route id).** A number naming one machine to the router, given
by the router's config to the PIN -- a machine cannot pick or claim one.

**Def. 3 (target).** A line of the router's directory: a route id, a name,
who may see it, and (`via`) the router it sits behind, if any.

**Def. 4 (end-to-end link).** The Geist link a client opens THROUGH the
router to a target (`connectGeistVia`). Its frames are the route frames'
payload; the router never has their key.

## 4. The config, line by line 🍣

`geist-hopd --write-config hop.toml` writes a complete, commented example.

```text
  key                 meaning
  ------------------  ----------------------------------------------------
  listen              where neighbours dial (default port 47658)
  id                  this router's own route id
  identity            its signing key, created on first start
  idleSeconds         a link silent this long is dropped (default 900);
                      linked machines ask something every 60 s
  [[peer]]            one per neighbour:
    pin                 its pin file
    id                  the route id this router gives it
    router              true for another geist-hopd: the ids it hands on
                        are believed (section 5)
    endpoint            for a router THIS one dials: dac://host:port
  [[target]]          one per directory line:
    id                  what clients address
    name                what `geist routes` shows (at most 32 bytes)
    visibleTo           pin SUBJECTS that may see and reach it; "*" = all
    via                 the router it sits behind; 0 = it links here
```

Who may reach whom is Bifrost's rule set (Bifrost docs/routing.md,
section 6). In short: a client reaches the targets visible to it; a target
may answer whoever wrote to it; "no such id" and "not for you" get the
same refusal, so ids cannot be probed.

## 5. Two routers ❧

```text
  phone ==> R1 (id 16) ==R1 dials==> R2 (id 17) <== NAS (id 32)

  R1  peer   phone.pin id 48
      peer   r2.pin    id 17  router = true  endpoint = "dac://r2:47658"
      target id 32 "nas" visibleTo ["phone"] via = 17

  R2  peer   r1.pin    id 16  router = true
      peer   nas.pin   id 32
      target id 32 "nas" visibleTo ["<R1's subject>"]
```

The NAS's answer finds its way back without any config for the phone on
R2: R2 notes "id 48 came through R1" when R1 hands it the phone's frames
(a return note, kept 120 s). Each router takes one hop from a counter; at
zero a frame is refused, so a mistaken loop between routers burns out.

## 6. What the router sees, and what it cannot ⌜guide⌟

```text
  sees                                 cannot see
  -----------------------------------  ---------------------------------
  which linked machine writes to       the request, the answer, the rows
  which, by route id                   (end-to-end keys never reach it)
  how many bytes, and when             the end-to-end handshake's
  the end-to-end frames' lengths       identities (sealed inside it)
```

A watcher on ONE link sees neither who a frame is for nor who it is from
(the address is sealed per link). A watcher on BOTH sides of the router
can match frames in to frames out by their payload, which is the same
bytes on both sides.

## 7. Edge cases and limits ୨୧

```text
  what                                   behaviour
  -------------------------------------  -----------------------------------------
  target unknown, or not visible to you  refused at once: "route refused:
                                         arrNoRoute"
  target known but not linked right now  also "arrNoRoute" -- the router does not
                                         tell a missing machine from a hidden one
  the next link could not take the       "arrUnreachable"; try later
  frame right now
  the NAS restarts                       it links again; the old link is replaced
  the router restarts                    geistd notices silence (3 minutes) and
                                         links again; clients reconnect
  a machine links twice                  the newer link replaces the older
  a router another one dials is down     retried every 10 s
  frames bigger than one datagram        the ordinary Geist package path, each
                                         piece its own route frame
  router dials block                     up to timeoutMs (2 s) per dial, rare
```
