# ---------------------------------------------------------------------
# Two desktops, one database each, exchanging rows over a real network
# ---------------------------------------------------------------------
#
# The two nodes are deliberately configured DIFFERENTLY, because the pair
# of settings that matter most are the ones an operator gets to choose:
#
#              alpha                          beta
#   preset     secure-app (encrypted)         app (plain)
#   rights     allowWrite = [ beta ]          trust = [ alpha ]
#   lease      holds it (writable daemon)     takes none (read-only)
#
# Which gives every claim in the README somewhere to fail:
#
#   * a peer may write only because the OPERATOR listed its pin under
#     allowWrite -- so beta writes to alpha, and alpha is refused by beta
#   * a writable daemon holds the store's write lease, so a local
#     `geist put` on alpha is refused while it runs
#   * a read-only daemon holds none, so a local `geist put` on beta works
#     AND the daemon notices the file moved underneath it
#   * an encrypted database leaves no plaintext on disk
#   * rows arriving from a peer keep the id that peer gave them

{ pkgs, geistPackage, module }:

let
  schema = "noteId:int,title:text,body:text";

  desktop = { address, secrets }: { config, lib, pkgs, ... }: {
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

    # Passwords are files, never command lines. 0440 root:geist so systemd
    # can load them as credentials and the CLI can read them as the same
    # user the daemon runs as.
    systemd.tmpfiles.rules =
      [ "d /run/geist-secrets 0755 root root -"
        "d /var/lib/geist/peers 0750 geist geist -"
      ]
      ++ lib.mapAttrsToList
        (name: value: "f /run/geist-secrets/${name} 0440 root geist - ${value}")
        secrets;

    # Started by hand in the test: a daemon cannot start before the pin of
    # the peer it trusts has arrived, and that exchange is the test.
    systemd.services.geistd.wantedBy = lib.mkForce [ ];

    system.stateVersion = "26.05";
  };
in
pkgs.testers.runNixOSTest {
  name = "geist-two-desktop-exchange";

  nodes.alpha = { lib, ... }: {
    imports = [
      (desktop {
        address = "192.168.50.10";
        secrets.alpha-db-pw = "alpha-at-rest-secret";
      })
    ];

    services.geistd = {
      enable = true;
      package = geistPackage;
      path = "/var/lib/geist/main";
      preset = "secure-app";
      passwordFile = "/run/geist-secrets/alpha-db-pw";
      identityPasswordFile = "/run/geist-secrets/alpha-db-pw";
      identityFile = "/var/lib/geist/alpha.id";
      subject = "alpha";
      listenHost = "192.168.50.10";
      openFirewall = true;
      quiet = false;
      # beta may READ AND WRITE. This is the whole grant: nothing beta
      # sends can widen it, and nothing it sends is needed to exercise it.
      allowWrite = [ "/var/lib/geist/peers/beta.pin" ];
    };

    # Reached with --config below. The point of generating it is that the
    # parser REFUSES an unknown key, so a module emitting the wrong name
    # for a setting is a failure rather than a silently ignored line.
    programs.geist-client = {
      enable = true;
      settings.database = {
        path = "/var/lib/geist/main";
        preset = "secure-app";
        passwordFile = "/run/geist-secrets/alpha-db-pw";
      };
    };
  };

  nodes.beta = { lib, ... }: {
    imports = [
      (desktop {
        address = "192.168.50.11";
        secrets.beta-id-pw = "beta-identity-secret";
      })
    ];

    services.geistd = {
      enable = true;
      package = geistPackage;
      path = "/var/lib/geist/main";
      preset = "app";
      identityPasswordFile = "/run/geist-secrets/beta-id-pw";
      identityFile = "/var/lib/geist/beta.id";
      subject = "beta";
      listenHost = "192.168.50.11";
      openFirewall = true;
      # alpha may only READ. No write lease is taken, so this desktop's
      # own CLI keeps working while the daemon serves.
      trust = [ "/var/lib/geist/peers/alpha.pin" ];
    };

    programs.geist-client.enable = true;
  };

  testScript = ''
    import re

    SCHEMA = "${schema}"
    ALPHA = "dac://192.168.50.10:47655"
    BETA = "dac://192.168.50.11:47655"
    ALPHA_PW = "/run/geist-secrets/alpha-db-pw"
    BETA_PW = "/run/geist-secrets/beta-id-pw"
    DB = "/var/lib/geist/main"

    def as_geist(node, command):
        """Everything runs as the service user: the identity files and the
        database belong to it, and a root-owned artifact left behind would
        break the next step in a way that has nothing to do with Geist."""
        return node.succeed(f"runuser -u geist -- {command} 2>&1")

    def as_geist_fails(node, command):
        return node.fail(f"runuser -u geist -- {command} 2>&1")

    def publish_pin(node, name, password):
        """`geistd --pin-out` mints the identity and writes the public half.
        It has to happen before the daemon starts, because the daemon
        refuses to start until the peer it trusts has a pin on disk."""
        as_geist(node, f"geistd --path {DB} --identity /var/lib/geist/{name}.id "
                       f"--identity-password-file {password} "
                       f"--subject {name} --pin-out /var/lib/geist/{name}.pin")

    def hand_over_pin(src, dst, name):
        """The out-of-band exchange, with the test driver as the sneakernet.
        A pin is public; this is the step that IS the trust decision."""
        blob = src.succeed(f"base64 -w0 /var/lib/geist/{name}.pin")
        dst.succeed(f"printf %s '{blob}' | base64 -d > /var/lib/geist/peers/{name}.pin")
        dst.succeed(f"chown geist:geist /var/lib/geist/peers/{name}.pin")

    start_all()
    # network-online.target is passive here: nothing requests it until the
    # daemon's own unit does, so waiting on it would wait for ever. What
    # matters is that the static address is actually up.
    for m, addr in ((alpha, "192.168.50.10"), (beta, "192.168.50.11")):
        m.wait_for_unit("multi-user.target")
        m.wait_until_succeeds(f"ip -4 addr show eth1 | grep -q {addr}", timeout=60)
    alpha.succeed("ping -c1 -W2 192.168.50.11")

    with subtest("each desktop mints an identity and they swap pins"):
        publish_pin(alpha, "alpha", ALPHA_PW)
        publish_pin(beta, "beta", BETA_PW)
        hand_over_pin(alpha, beta, "alpha")
        hand_over_pin(beta, alpha, "beta")

    with subtest("both databases exist before anything serves them"):
        as_geist(alpha, f"geist --path {DB} --preset secure-app "
                        f"--password-file {ALPHA_PW} init --schema '{SCHEMA}'")
        as_geist(alpha, f"geist --path {DB} --preset secure-app "
                        f"--password-file {ALPHA_PW} put noteId=1 "
                        f"title=alpha-first body=written-locally")
        as_geist(beta, f"geist --path {DB} init --schema '{SCHEMA}'")
        as_geist(beta, f"geist --path {DB} put noteId=9 title=beta-first "
                       f"body=written-locally")

    with subtest("the daemons start and report the rights they were given"):
        alpha.systemctl("start geistd")
        beta.systemctl("start geistd")
        alpha.wait_for_unit("geistd.service")
        beta.wait_for_unit("geistd.service")
        alpha.wait_until_succeeds("ss -lunp | grep -q 47655", timeout=30)
        beta.wait_until_succeeds("ss -lunp | grep -q 47655", timeout=30)

        journal = alpha.succeed("journalctl -u geistd --no-pager")
        assert "read-write (holds the write lease)" in journal, journal
        assert "may write" in journal, journal
        journal = beta.succeed("journalctl -u geistd --no-pager")
        assert "read-only (takes no lease)" in journal, journal
        assert "read only" in journal, journal

    with subtest("a writable daemon holds the lease, so local writes stop"):
        # Not a lock file left lying around: the daemon is the writer, and
        # it says so by name rather than failing at save time.
        refused = as_geist_fails(alpha, f"geist --path {DB} --preset secure-app "
                                        f"--password-file {ALPHA_PW} put noteId=2 "
                                        f"title=should-not-work body=x")
        assert "already open for writing" in refused, refused
        # It names the holder. "Refused" on its own would leave an operator
        # guessing which process to stop.
        assert "held by pid" in refused, refused

    with subtest("a peer listed under allowWrite may write across the wire"):
        out = as_geist(beta, f"geist --remote {ALPHA} --identity /var/lib/geist/beta.id "
                             f"--peer-pin /var/lib/geist/peers/alpha.pin "
                             f"--password-file {BETA_PW} "
                             f"put noteId=2 title=from-beta body=over-the-wire")
        assert "1 row" in out, out

    with subtest("the acknowledged row is on alpha's disk, not just in RAM"):
        # The daemon told beta the row was stored, so a crash here must not
        # lose it. alpha's own CLI reads the file the daemon is serving.
        listed = as_geist(alpha, f"geist --path {DB} --preset secure-app "
                                 f"--password-file {ALPHA_PW} list")
        assert "from-beta" in listed, listed
        assert "alpha-first" in listed, listed

    with subtest("a peer listed under trust alone is refused, and told why"):
        refused = as_geist_fails(alpha,
            f"geist --remote {BETA} --identity /var/lib/geist/alpha.id "
            f"--peer-pin /var/lib/geist/peers/beta.pin "
            f"--password-file {ALPHA_PW} put noteId=3 title=nope body=nope")
        assert "may read but not" in refused, refused
        assert "allow-write" in refused, refused

    with subtest("catching up gives beta alpha's rows under alpha's ids"):
        MIRROR = "/var/lib/geist/mirror"
        out = as_geist(beta, f"geist sync --path {MIRROR} --remote {ALPHA} "
                             f"--identity /var/lib/geist/beta.id "
                             f"--peer-pin /var/lib/geist/peers/alpha.pin "
                             f"--password-file {BETA_PW}")
        assert "applied 2 row(s)" in out, out

        # The mirror is a database in its own right, and it is NOT
        # encrypted: what a peer stores at rest is its own business, and
        # only the rows travel.
        mirrored = as_geist(beta, f"geist --path {MIRROR} --json list")
        assert "from-beta" in mirrored, mirrored
        assert "alpha-first" in mirrored, mirrored

        # Same ids on both sides. This is what makes a later update from
        # alpha land ON the row rather than beside it.
        origin = as_geist(alpha, f"geist --path {DB} --preset secure-app "
                                 f"--password-file {ALPHA_PW} --json list")
        ids_here = sorted(re.findall(r'"__rowId":\s*"?(\d+)', origin))
        ids_there = sorted(re.findall(r'"__rowId":\s*"?(\d+)', mirrored))
        assert ids_here and ids_here == ids_there, (ids_here, ids_there)

        # Asking again moves nothing: the cursor was kept.
        again = as_geist(beta, f"geist sync --path {MIRROR} --remote {ALPHA} "
                               f"--identity /var/lib/geist/beta.id "
                               f"--peer-pin /var/lib/geist/peers/alpha.pin "
                               f"--password-file {BETA_PW}")
        assert "applied 0 row(s)" in again, again

    with subtest("a read-only daemon leaves its own desktop free to write"):
        # beta's daemon took no lease, so this succeeds -- and the daemon
        # then notices the generation moved underneath it and reloads,
        # which is why alpha can see the row without beta restarting.
        as_geist(beta, f"geist --path {DB} put noteId=10 title=beta-later "
                       f"body=added-while-serving")
        beta.wait_until_succeeds(
            "journalctl -u geistd --no-pager | grep -q 'reloaded'", timeout=30)
        seen = as_geist(alpha, f"geist --remote {BETA} "
                               f"--identity /var/lib/geist/alpha.id "
                               f"--peer-pin /var/lib/geist/peers/beta.pin "
                               f"--password-file {ALPHA_PW} list")
        assert "beta-later" in seen, seen

    with subtest("alpha's database is encrypted at rest"):
        # The values are the test: a preset named "secure" that wrote
        # plaintext would pass every functional check above.
        alpha.fail(f"grep -r --binary-files=text 'written-locally' {DB}")
        alpha.fail(f"grep -r --binary-files=text 'over-the-wire' {DB}")
        # And the plain one is genuinely plain, so the check above can fail.
        beta.succeed(f"grep -r --binary-files=text 'written-locally' {DB}")

    with subtest("the module's generated client config is one geist accepts"):
        # It supplies path, preset and password file, so none are typed.
        # An unknown key here would be an error, not a shrug.
        listed = as_geist(alpha,
            "geist --config /etc/geist/userconfig.toml list")
        assert "from-beta" in listed, listed

    with subtest("both daemons are still healthy"):
        alpha.succeed("systemctl is-active geistd")
        beta.succeed("systemctl is-active geistd")
  '';
}
