# ---------------------------------------------------------------------
# Three desktops in a chain: does a row survive being passed on?
# ---------------------------------------------------------------------
#
#   origin ---sync---> middle ---sync---> tail
#   192.168.60.10      192.168.60.11      192.168.60.12
#
# `tail` and `origin` never exchange a Geist frame. They sit on one network
# and can route to each other -- the test checks that, so nothing below can
# be waved away as unreachability -- but neither holds the other's pin, and
# the test checks that a session between them cannot be opened.
#
# THE MIDDLE DESKTOP IS NOT A RELAY COMPONENT. There is no forwarding code
# and no such mode: `middle` follows `origin` with exactly the call `tail`
# uses to follow `middle`, and serves what it has with exactly the daemon
# `origin` runs. That it happens to sit between two others is not something
# it knows.
#
# WHAT WOULD BREAK IT. Rows carry their own identity, so the id `origin`
# minted has to arrive at `tail` unchanged, two hops later. If any hop
# re-minted ids, the chain would still LOOK like it worked -- rows would
# arrive and counts would match -- and would then diverge for ever the
# first time `origin` updated a row, because the update would land beside
# its target rather than on it. So this test checks the ids, and then
# checks an update and a delete actually converge.
#
# The middle also has to take NO write lease while serving, or it could not
# apply what it receives; it is configured read-only for exactly that
# reason, and its daemon picks up its own catch-up by reloading.

{ pkgs, geistPackage, module }:

let
  schema = "noteId:int,title:text,body:text";

  # One shape for all three: what differs between them is who they trust
  # and which way they face, which is the point.
  node = { address, subject, trusts }: { config, lib, pkgs, ... }: {
    imports = [ module ];

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

    systemd.tmpfiles.rules = [
      "d /run/geist-secrets 0755 root root -"
      "d /var/lib/geist/peers 0750 geist geist -"
      "f /run/geist-secrets/id.pw 0440 root geist - ${subject}-identity-secret"
    ];

    systemd.services.geistd.wantedBy = lib.mkForce [ ];

    services.geistd = {
      enable = true;
      package = geistPackage;
      path = "/var/lib/geist/main";
      preset = "app";
      identityPasswordFile = "/run/geist-secrets/id.pw";
      identityFile = "/var/lib/geist/${subject}.id";
      listenHost = address;
      openFirewall = true;
      inherit subject;
      # READ ONLY, on every node in the chain. A daemon granted writes would
      # take the store's write lease, and the node could then no longer
      # apply what it catches up with -- the catch-up is a local write.
      trust = map (p: "/var/lib/geist/peers/${p}.pin") trusts;
    };

    programs.geist-client.enable = true;

    system.stateVersion = "26.05";
  };
in
pkgs.testers.runNixOSTest {
  name = "geist-three-desktop-relay";

  nodes.origin = node {
    address = "192.168.60.10";
    subject = "origin";
    trusts = [ "middle" ];
  };

  nodes.middle = node {
    address = "192.168.60.11";
    subject = "middle";
    trusts = [ "tail" ];
  };

  # Follows only. Nothing is pinned to it, so its daemon has nobody to
  # serve -- which is why it is never started.
  nodes.tail = node {
    address = "192.168.60.12";
    subject = "tail";
    trusts = [ "middle" ];
  };

  testScript = ''
    import re

    SCHEMA = "${schema}"
    DB = "/var/lib/geist/main"
    PW = "/run/geist-secrets/id.pw"
    ORIGIN = "dac://192.168.60.10:47655"
    MIDDLE = "dac://192.168.60.11:47655"

    def as_geist(node, command):
        return node.succeed(f"runuser -u geist -- {command} 2>&1")

    def publish_pin(node, name):
        as_geist(node, f"geistd --path {DB} --identity /var/lib/geist/{name}.id "
                       f"--identity-password-file {PW} --subject {name} "
                       f"--pin-out /var/lib/geist/{name}.pin")

    def hand_over_pin(src, dst, name):
        blob = src.succeed(f"base64 -w0 /var/lib/geist/{name}.pin")
        dst.succeed(f"printf %s '{blob}' | base64 -d > /var/lib/geist/peers/{name}.pin")
        dst.succeed(f"chown geist:geist /var/lib/geist/peers/{name}.pin")

    def row_ids(node, path):
        """Ids as the node itself reports them, in sorted order, so two
        nodes can be compared without depending on row order."""
        out = as_geist(node, f"geist --path {path} --json list --limit 100")
        return sorted(re.findall(r'"__rowId":\s*"?(\d+)', out))

    def titles(node, path):
        out = as_geist(node, f"geist --path {path} --json list --limit 100")
        return sorted(re.findall(r'"title":\s*"([^"]*)"', out))

    def catch_up(node, name, remote, peer):
        """One hop: `node` (identity `name`) catches up with `peer` at
        `remote`. The SAME call at both ends of the chain -- which is the
        claim the whole test exists to check."""
        return as_geist(node, f"geist sync --path {DB} --remote {remote} "
                              f"--identity /var/lib/geist/{name}.id "
                              f"--peer-pin /var/lib/geist/peers/{peer}.pin "
                              f"--password-file {PW}")

    start_all()
    # network-online.target is passive here: nothing requests it until the
    # daemon's own unit does, so waiting on it would wait for ever. What
    # matters is that the static address is actually up.
    for m, addr in ((origin, "192.168.60.10"), (middle, "192.168.60.11"),
                    (tail, "192.168.60.12")):
        m.wait_for_unit("multi-user.target")
        m.wait_until_succeeds(f"ip -4 addr show eth1 | grep -q {addr}", timeout=60)

    with subtest("identities and the two pin exchanges the chain needs"):
        publish_pin(origin, "origin")
        publish_pin(middle, "middle")
        publish_pin(tail, "tail")
        # Hop one: origin <-> middle.
        hand_over_pin(origin, middle, "origin")
        hand_over_pin(middle, origin, "middle")
        # Hop two: middle <-> tail. origin is not part of this, and never
        # learns tail exists.
        hand_over_pin(middle, tail, "middle")
        hand_over_pin(tail, middle, "tail")
        origin.fail("test -e /var/lib/geist/peers/tail.pin")
        tail.fail("test -e /var/lib/geist/peers/origin.pin")

    with subtest("the far ends share a network but no trust"):
        # They can route to each other -- so nothing below is explained by
        # tail being unable to find origin. What it lacks is a pin, in
        # either direction, and pinned trust is not optional.
        origin.succeed("ping -c1 -W2 192.168.60.12")
        tail.fail(f"timeout 20 geist --remote {ORIGIN} "
                  f"--identity /var/lib/geist/tail.id "
                  f"--peer-pin /var/lib/geist/peers/middle.pin "
                  f"--password-file {PW} list")

    with subtest("origin has rows; the other two have nothing"):
        as_geist(origin, f"geist --path {DB} init --schema '{SCHEMA}'")
        for n, t in ((1, "first"), (2, "second"), (3, "third")):
            as_geist(origin, f"geist --path {DB} put noteId={n} title={t} "
                             f"body=from-origin")
        origin_ids = row_ids(origin, DB)
        assert len(origin_ids) == 3, origin_ids
        middle.fail(f"test -e {DB}")
        tail.fail(f"test -e {DB}")

    with subtest("hop one: middle catches up with origin, from empty"):
        # middle has no database and no schema. It gets both from the
        # answer, which is what joining a chain by naming one peer means.
        origin.systemctl("start geistd")
        origin.wait_for_unit("geistd.service")
        origin.wait_until_succeeds("ss -lunp | grep -q 47655", timeout=30)

        out = catch_up(middle, "middle", ORIGIN, "origin")
        assert "applied 3 row(s)" in out, out
        assert row_ids(middle, DB) == origin_ids, (row_ids(middle, DB), origin_ids)

    with subtest("hop two: tail catches up with middle, from empty"):
        middle.systemctl("start geistd")
        middle.wait_for_unit("geistd.service")
        middle.wait_until_succeeds("ss -lunp | grep -q 47655", timeout=30)
        # A read-only daemon takes no lease, which is what let middle apply
        # the rows above while being ready to serve them here.
        assert "read-only (takes no lease)" in middle.succeed(
            "journalctl -u geistd --no-pager")

        out = catch_up(tail, "tail", MIDDLE, "middle")
        assert "applied 3 row(s)" in out, out

    with subtest("THE POINT: tail holds origin's ids, two hops away"):
        assert row_ids(tail, DB) == origin_ids, (row_ids(tail, DB), origin_ids)
        assert titles(tail, DB) == ["first", "second", "third"], titles(tail, DB)

    with subtest("an update and a delete converge along the whole chain"):
        # Both are log entries rather than edits in place, so both travel
        # the same way the original rows did.
        target = origin_ids[0]
        as_geist(origin, f"geist --path {DB} set {target} title=corrected")
        as_geist(origin, f"geist --path {DB} delete {origin_ids[2]}")

        # origin's daemon is read-only, so it reloads rather than serving
        # the snapshot it started with.
        origin.wait_until_succeeds(
            "journalctl -u geistd --no-pager | grep -q 'reloaded'", timeout=30)

        out = catch_up(middle, "middle", ORIGIN, "origin")
        assert "applied 2 row(s)" in out, out
        middle.wait_until_succeeds(
            "journalctl -u geistd --no-pager | grep -q 'reloaded'", timeout=30)

        out = catch_up(tail, "tail", MIDDLE, "middle")
        assert "applied 2 row(s)" in out, out

        # Same visible state at both ends of a chain whose ends have never
        # spoken: one row renamed under its original id, one row gone.
        assert titles(tail, DB) == ["corrected", "second"], titles(tail, DB)
        assert titles(origin, DB) == titles(tail, DB)
        assert row_ids(origin, DB) == row_ids(tail, DB)
        assert target in row_ids(tail, DB), (target, row_ids(tail, DB))
        assert origin_ids[2] not in row_ids(tail, DB)

    with subtest("catching up again is a single empty request"):
        out = catch_up(tail, "tail", MIDDLE, "middle")
        assert "applied 0 row(s)" in out, out

    with subtest("both serving daemons are still healthy"):
        origin.succeed("systemctl is-active geistd")
        middle.succeed("systemctl is-active geistd")
        tail.fail("systemctl is-active geistd")
  '';
}
