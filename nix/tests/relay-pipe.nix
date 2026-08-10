# ---------------------------------------------------------------------
# A phone, a desktop and a laptop -- moving messages, storing nothing
# ---------------------------------------------------------------------
#
# The database tests prove rows survive a network. This one proves the
# other half of the idea: the same pinned transport, with a PIPE where the
# store would be.
#
#              phone                pc                    laptop
#   role       sends                relays                collects
#   rights     allowWrite           --                    trust
#   sink       --                   exec + a file relay   --
#
# The flow being checked is the one it was built for:
#
#   arecord | geist-relay send --stream voice
#        -> pinned handshake -> geist-relayd --to exec
#        -> the command's stdin -> its stdout -> back to the phone
#
# Which gives every claim in docs/relay.md somewhere to fail:
#
#   * a message reaches a command's STDIN and its stdout is the reply
#   * the command is told who sent it, from the PIN rather than the payload
#   * a peer pinned for reading may collect but not send
#   * a stream nobody configured is refused by name
#   * a second peer collects from the spool without consuming the first's
#   * a JSON log holds binary as base64 and text as text
#   * the relay is not a database, and says so to a database client
#   * nothing was written to a store, because there is no store

{ pkgs, geistPackage, relayModule }:

let
  # The stand-in transcriber. Uppercasing is not the point; being a real
  # program that reads stdin, is told about the message in its
  # environment, and answers on stdout is.
  transcriber = pkgs.writeShellScript "fake-transcriber" ''
    printf '[%s/%s] ' "$GEIST_FROM" "$GEIST_STREAM"
    tr 'a-z' 'A-Z'
  '';

  # createUser: the relay module makes this account itself, so only the
  # nodes that do NOT import it declare one. They still need it: keys and
  # pins belong to the same user everywhere, or a file written by one step
  # is unreadable by the next.
  node = { address, secrets, createUser ? true }: { config, lib, pkgs, ... }: {
    virtualisation = {
      cores = 2;
      memorySize = 1024;
      diskSize = 2048;
      vlans = [ 1 ];
    };

    networking = {
      useDHCP = false;
      interfaces.eth1.ipv4.addresses = [
        { inherit address; prefixLength = 24; }
      ];
      firewall.enable = true;
    };

    environment.systemPackages = [ geistPackage ];

    users.users = lib.optionalAttrs createUser {
      geist-relay = {
        isSystemUser = true;
        group = "geist-relay";
        home = "/var/lib/geist-relay";
        createHome = true;
      };
    };
    users.groups = lib.optionalAttrs createUser { geist-relay = { }; };

    systemd.tmpfiles.rules =
      [ "d /run/geist-secrets 0755 root root -"
        "d /var/lib/geist-relay 0750 geist-relay geist-relay -"
        "d /var/lib/geist-relay/peers 0750 geist-relay geist-relay -"
      ]
      ++ lib.mapAttrsToList
        (name: value:
          "f /run/geist-secrets/${name} 0440 root geist-relay - ${value}")
        secrets;

    system.stateVersion = "26.05";
  };
in
pkgs.testers.runNixOSTest {
  name = "geist-relay-pipe";

  nodes.phone = { lib, ... }: {
    imports = [
      (node {
        address = "192.168.50.20";
        secrets.phone-id-pw = "phone-identity-secret";
      })
    ];
  };

  nodes.pc = { lib, ... }: {
    imports = [
      relayModule
      (node {
        address = "192.168.50.21";
        secrets.pc-id-pw = "pc-identity-secret";
        createUser = false;
      })
    ];

    services.geist-relay = {
      enable = true;
      package = geistPackage;
      subject = "pc";
      listenHost = "192.168.50.21";
      openFirewall = true;
      identityFile = "/var/lib/geist-relay/pc.id";
      identityPasswordFile = "/run/geist-secrets/pc-id-pw";
      # The phone may SEND, which with `to = exec` means the phone's
      # messages are what start the command. The laptop may only COLLECT.
      allowWrite = [ "/var/lib/geist-relay/peers/phone.pin" ];
      trust = [ "/var/lib/geist-relay/peers/laptop.pin" ];
      to = "exec";
      exec = "${transcriber}";
      execTimeoutMs = 10000;
      streams = [ "voice" ];
      spool = 8;
    };

    # Started by hand in the test: a relay cannot start before the pins of
    # the peers it trusts have arrived, and that exchange is the test.
    systemd.services.geist-relayd.wantedBy = lib.mkForce [ ];

    networking.firewall.allowedUDPPorts = [ 47657 ];
  };

  nodes.laptop = { lib, ... }: {
    imports = [
      (node {
        address = "192.168.50.22";
        secrets.laptop-id-pw = "laptop-identity-secret";
      })
    ];
  };

  testScript = ''
    import json

    # Interpolated by Nix, not by Python: an f-string below would treat a
    # bare {geistPackage} as one of its own placeholders.
    RELAY_BIN = "${geistPackage}/bin/geist-relayd"

    PC = "dac://192.168.50.21:47656"
    PC_LOG = "dac://192.168.50.21:47657"
    KEYS = "/var/lib/geist-relay"
    INBOX = "/var/lib/geist-relay/inbox.jsonl"
    # "binary\x00\xff": text, a NUL, and a byte that is not valid UTF-8.
    BINARY = "YmluYXJ5AP8="

    def as_relay(machine, command):
        """Everything runs as the service user: the identity files belong
        to it, and a root-owned key left behind would break the next step
        for a reason that has nothing to do with Geist."""
        return machine.succeed(f"runuser -u geist-relay -- {command} 2>&1")

    def as_relay_fails(machine, command):
        return machine.fail(f"runuser -u geist-relay -- {command} 2>&1")

    def client(machine, name, verb, extra):
        """One geist-relay invocation, with this node's identity and the
        relay's pin. Pinned trust means both are always required."""
        return (f"geist-relay {verb} --remote {PC} "
                f"--identity {KEYS}/{name}.id "
                f"--identity-password-file /run/geist-secrets/{name}-id-pw "
                f"--subject {name} --peer-pin {KEYS}/peers/pc.pin {extra}")

    def publish_pin(machine, name):
        """`geist-relay pin` mints the identity and writes the public half.
        The relay refuses to start until the pins it trusts are on disk."""
        as_relay(machine, f"geist-relay pin --identity {KEYS}/{name}.id "
                          f"--identity-password-file /run/geist-secrets/{name}-id-pw "
                          f"--subject {name} --pin-out {KEYS}/{name}.pin")

    def hand_over_pin(src, dst, name):
        """The out-of-band exchange, with the test driver as the sneakernet.
        A pin is public; this step IS the trust decision."""
        blob = src.succeed(f"base64 -w0 {KEYS}/{name}.pin")
        dst.succeed(f"printf %s '{blob}' | base64 -d > {KEYS}/peers/{name}.pin")
        dst.succeed(f"chown geist-relay:geist-relay {KEYS}/peers/{name}.pin")

    start_all()
    # network-online.target is passive here: nothing requests it until the
    # relay's own unit does, so waiting on it would wait for ever. What
    # matters is that the static address is actually up.
    for m, addr in ((phone, "192.168.50.20"), (pc, "192.168.50.21"),
                    (laptop, "192.168.50.22")):
        m.wait_for_unit("multi-user.target")
        m.wait_until_succeeds(f"ip -4 addr show eth1 | grep -q {addr}", timeout=60)
    phone.succeed("ping -c1 -W2 192.168.50.21")

    with subtest("every node mints an identity and the pins are exchanged"):
        publish_pin(phone, "phone")
        publish_pin(pc, "pc")
        publish_pin(laptop, "laptop")
        hand_over_pin(phone, pc, "phone")
        hand_over_pin(laptop, pc, "laptop")
        hand_over_pin(pc, phone, "pc")
        hand_over_pin(pc, laptop, "pc")

    with subtest("the relay starts and reports the pipe it was given"):
        pc.systemctl("start geist-relayd")
        pc.wait_for_unit("geist-relayd.service")
        pc.wait_until_succeeds("ss -lunp | grep -q 47656", timeout=30)

        journal = pc.succeed("journalctl -u geist-relayd --no-pager")
        assert "to:      exec" in journal, journal
        assert "fake-transcriber" in journal, journal
        assert "phone  (may send)" in journal, journal
        assert "laptop  (may collect)" in journal, journal
        assert "streams: voice" in journal, journal

    with subtest("a message reaches the command's stdin and answers back"):
        # The whole point, in one line: bytes leave the phone, a program on
        # the desktop reads them on stdin, and what it printed comes back.
        out = as_relay(phone, "sh -c \"printf 'hello from the phone' | " +
                       client(phone, "phone", "send", "--stream voice") + "\"")
        assert out.strip() == "[phone/voice] HELLO FROM THE PHONE", out

    with subtest("the command is told who sent it, from the pin"):
        # `phone` in that answer is not something the payload said. It is
        # the subject on the certificate the handshake verified, so a
        # message claiming to be from somebody else changes nothing.
        out = as_relay(phone, "sh -c \"printf 'from: laptop' | " +
                       client(phone, "phone", "send", "--stream voice") + "\"")
        assert out.strip() == "[phone/voice] FROM: LAPTOP", out

    with subtest("a peer pinned for reading may collect but not send"):
        refused = as_relay_fails(laptop, "sh -c \"printf 'not allowed' | " +
                                 client(laptop, "laptop", "send", "--stream voice") + "\"")
        assert "may read but not send" in refused, refused
        assert "--allow-write" in refused, refused

    with subtest("a stream nobody configured is refused by name"):
        refused = as_relay_fails(phone, "sh -c \"printf 'x' | " +
                                 client(phone, "phone", "send", "--stream secrets") + "\"")
        assert "takes no stream 'secrets'" in refused, refused
        assert "it takes voice" in refused, refused

    with subtest("the laptop collects what the phone sent, from the spool"):
        # The messages went to a command AND to the queue: a relay piping
        # to a transcriber can still be read by somebody else.
        out = as_relay(laptop, client(laptop, "laptop", "poll",
                                      "--stream voice --format json"))
        lines = [json.loads(l) for l in out.strip().splitlines()]
        assert len(lines) == 2, out
        assert lines[0]["from"] == "phone", lines
        assert lines[0]["body"] == "hello from the phone", lines
        assert lines[1]["ordinal"] == 2, lines

        # Asking again hands over nothing: this reader's position was kept.
        again = as_relay(laptop, client(laptop, "laptop", "poll",
                                        "--stream voice --format json"))
        assert again.strip() == "", again

    with subtest("a second reader sees everything, not the leftovers"):
        out = as_relay(laptop, client(laptop, "laptop", "poll",
                                      "--stream voice --as second --format json"))
        assert len(out.strip().splitlines()) == 2, out

    with subtest("a relay logging to JSON keeps text as text and bytes as base64"):
        # A second relay, same identity, plain flags instead of the module:
        # the file sink an operator reaches for when the messages are notes
        # rather than audio.
        pc.succeed(
            "systemd-run --unit=geist-relay-log --uid=geist-relay "
            "--working-directory=/var/lib/geist-relay "
            f"{RELAY_BIN} "
            "--listen dac://192.168.50.21:47657 "
            f"--identity {KEYS}/pc.id "
            "--identity-password-file /run/geist-secrets/pc-id-pw "
            "--subject pc "
            f"--allow-write {KEYS}/peers/phone.pin "
            f"--to file --file {INBOX} --format json")
        pc.wait_until_succeeds("ss -lunp | grep -q 47657", timeout=30)

        as_relay(phone, "sh -c \"printf 'a note worth keeping' | " +
                 client(phone, "phone", "send", "--stream notes").replace(PC, PC_LOG) + "\"")

        # The binary case comes from a FILE rather than a pipeline: bytes
        # like NUL do not survive being written into a shell command, and
        # what is being checked is the relay's handling of them, not the
        # test driver's quoting.
        phone.succeed(f"printf %s '{BINARY}' | base64 -d > {KEYS}/blob.bin")
        phone.succeed(f"chown geist-relay:geist-relay {KEYS}/blob.bin")
        as_relay(phone, client(phone, "phone", "send",
                               f"--stream notes --file {KEYS}/blob.bin"
                               ).replace(PC, PC_LOG))

        pc.wait_until_succeeds(f"test $(wc -l < {INBOX}) -ge 2", timeout=30)
        records = [json.loads(l) for l in
                   pc.succeed(f"cat {INBOX}").strip().splitlines()]
        assert records[0]["body"] == "a note worth keeping", records
        assert records[0]["from"] == "phone", records
        assert records[0]["stream"] == "notes", records
        # A NUL cannot go in a JSON string, and escaping it away would
        # change the message, so it travels as base64 instead.
        assert "body" not in records[1], records
        assert records[1]["base64"] == BINARY, records
        assert records[1]["bytes"] == 8, records

    with subtest("a database client is told this is not a database"):
        # The relay speaks the same wire, so `geist` reaches it and gets a
        # real answer rather than a timeout or a silent empty list.
        # `geist` seals its identity with the database password, so that is
        # the flag its identity file is opened with here.
        refused = as_relay_fails(phone,
            f"geist --remote {PC} --identity {KEYS}/phone.id "
            f"--password-file /run/geist-secrets/phone-id-pw "
            f"--peer-pin {KEYS}/peers/pc.pin list")
        assert "not a database" in refused, refused
        assert "geistd" in refused, refused

    with subtest("nothing was stored, because there is nothing to store with"):
        # No store root, no manifest, no lease -- the relay's state
        # directory holds keys and the log it was told to write, and that
        # is all.
        pc.fail(f"find {KEYS} -name '*.geist*' | grep -q .")
        pc.fail(f"find {KEYS} -name 'manifest*' | grep -q .")
        listing = pc.succeed(f"ls {KEYS}")
        assert "inbox.jsonl" in listing, listing

    with subtest("both relays are still healthy"):
        pc.succeed("systemctl is-active geist-relayd")
        pc.succeed("systemctl is-active geist-relay-log")
        journal = pc.succeed("journalctl -u geist-relayd --no-pager")
        assert "refused" in journal, journal
  '';
}
