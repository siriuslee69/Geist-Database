# Device monitor

Build the optional desktop UI (install `webui@2.5.0.2` with Nimble first),
the headless tools and the Android app:

```sh
nimble buildWebui -d:preset=device-monitor
nimble buildServerMonitor -d:preset=device-monitor
nimble buildCliMonitor -d:preset=device-monitor
nimble buildAndroid
nimble installAndroid
```

The UI is optional: ordinary database builds have no WebUI dependency.
Android needs the SDK plus NDK 28.2.13676358 and Gradle; the APK is under
`android/geistmonitor/build/outputs/apk/debug/`. Desktop and Android share
the page in `assets/monitor/` and the client in `src/clients/monitor/`.

Provision each device's private root with `geist-monitor-cli ROOT provision
SUBJECT`, using `pc`, `phone`, `vps-relay` and `vps-store` as subjects. The
Android app provisions `phone` on first start. Export the shared symmetric
key once with `geist-monitor-cli ROOT export-psk PRIVATE_WORD_FILE`, import
it on each other root with `import-psk`, then remove the plaintext transfer
file. Exchange only `keys/pairs/<subject>.pin` files into `peers/`.

The PC root defaults to `~/.config/geist-monitor`. Android keeps its root in
the application's private `files/monitor/` folder. Both need this public
endpoint file as `config.json`:

```json
{"subject":"pc","relay":"dac://VPS_ADDRESS:47656","store":"dac://VPS_ADDRESS:47655"}
```

Use `phone` for the phone's subject. The client pins are named
`peers/vps-relay.pin` and `peers/vps-store.pin`. On the VPS, each root holds
`peers/pc.pin` and `peers/phone.pin`. A missing or wrong factor stops the
connection; the client does not choose another mode, mask or protocol.

For persistent VPS services import `nix/device-monitor-module.nix` and set
`services.geistDeviceMonitor.enable`, `user`, `executable` and `dataDir`.
That root contains `relay/` and `store/`. The module creates
`geist-device-relay.service` and `geist-device-store.service`, starts them
at boot, and opens only UDP 47655 and 47656. The hosting provider's firewall
must allow those two ports too. [The port registry](ports.md) reserves
47650–47659 for Geist within this workspace.

`dataDir/store/messages/` is the durable Geist store. Each daemon keeps
`debug.jsonl` plus one rotated `.previous` file (8 MiB each), including peer,
mode, masks, session, handshake steps, byte counts and errors. `service.log`
captures startup failures through systemd. Client debug logs use the same
bounded JSON-lines format in the device root. Passwords and keys stay in
the private roots; none are included in the repository or debug events.

The monitor uses Geist's public APIs for keys, connections, messages and
storage. Bifrost and Tyr stay behind those APIs.

```nim
import geist/network

var
  shared = initGeistSharedKey("devices", keyBytes)
  policy = defaultTriggerPolicy()
policy.startTier = gtRecovery
var connection = connectGeist(address, identity, peerPin, policy,
  timeoutMs = 60000, shared = shared, observer = logEvent)
```

The shared key enables AM1P+S: both the symmetric proof and the pinned
signatures must succeed. A failed check stops the connection. The deployment
starts at `recovery`, which retires every lower tier. No other network
protocol is attempted.

```text
 PC monitor <-- Geist AM1P+S / AME / FOMKE / DAC --> VPS relay
 Phone      <-- Geist AM1P+S / AME / FOMKE / DAC ------^
 PC / Phone <-- Geist AM1P+S / AME / FOMKE / DAC --> VPS store
```

Each device creates its own signing identity with Geist. Only public pins
are exchanged. A shared symmetric key is generated once with Geist and
imported into the other devices' sealed Geist key folders.

The relay holds a bounded mailbox in memory; each recipient polls its own
stream. It needs no inbound connection to the PC or phone. The store writes
messages to a Geist database before acknowledging them and returns an echo.

Network observers report handshake steps, authentication mode, masks,
session identifiers, peers, byte counts and failures. They never receive
secret keys or decrypted message bodies. Persistent service logs retain
these events across restarts.
