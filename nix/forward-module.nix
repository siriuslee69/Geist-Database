# ---------------------------------------------------------------------
# NixOS module <- geist-forwardd, the VPS end of Client -> VPS -> Home
# ---------------------------------------------------------------------
#
#   services.geist-forward = {
#     enable = true;
#     listenHost = "0.0.0.0";
#     openFirewall = true;
#     home = "10.8.0.2:47655";      # where geistd runs, seen from THIS machine
#   };
#
# The forwarder holds no key and opens no frame, so this module has no
# identity, no pins and no state. Clients pin the HOME server's key and
# dial this machine's address; the handshake is made between those two.
# See docs/forwarding.md.
#
# `home` has to be reachable from this machine: a VPN address (WireGuard,
# Tailscale), a forwarded port, or a public IPv6 address.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.geist-forward;

  forwardArgs =
    [ "--listen" "dac://${cfg.listenHost}:${toString cfg.listenPort}" ]
    ++ [ "--to" "dac://${cfg.home}" ]
    ++ [ "--max-clients" (toString cfg.maxClients) ]
    ++ [ "--client-idle" (toString cfg.clientIdleSeconds) ]
    ++ [ "--ping" (toString cfg.pingSeconds) ]
    ++ [ "--silent" (toString cfg.silentSeconds) ]
    ++ [ "--buffer" (toString cfg.bufferDatagrams) ]
    ++ [ "--buffer-bytes" (toString cfg.bufferBytes) ]
    ++ [ "--report" (toString cfg.reportSeconds) ]
    ++ lib.optional cfg.followHome "--follow-home"
    ++ cfg.extraArgs;
in
{
  options.services.geist-forward = with lib; {
    enable = mkEnableOption "the Geist datagram forwarder (VPS end)";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./default.nix { };
      defaultText = literalExpression "pkgs.callPackage ./default.nix { }";
      description = "Package providing geist-forwardd.";
    };

    listenHost = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Address clients dial. The public address of this machine.";
    };

    listenPort = mkOption {
      type = types.port;
      default = 47655;
      description = "UDP port clients dial. The same as geistd's, so a client only changes the host.";
    };

    home = mkOption {
      type = types.str;
      example = "10.8.0.2:47655";
      description = ''
        host:port of the home server, as reachable FROM this machine.
        A name is resolved once, at start.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open listenPort (UDP) in the NixOS firewall.";
    };

    maxClients = mkOption {
      type = types.int;
      default = 512;
      description = "Clients held at once. A newcomer is refused when full; nobody is pushed out.";
    };

    clientIdleSeconds = mkOption {
      type = types.int;
      default = 120;
      description = "Seconds before a quiet client loses its place.";
    };

    pingSeconds = mkOption {
      type = types.int;
      default = 20;
      description = "Seconds between \"still there?\" pings to home.";
    };

    silentSeconds = mkOption {
      type = types.int;
      default = 60;
      description = "Seconds of silence before home counts as away. Must exceed pingSeconds.";
    };

    bufferDatagrams = mkOption {
      type = types.int;
      default = 64;
      description = "Datagrams held for an away home. Covers a reboot, not an outage.";
    };

    bufferBytes = mkOption {
      type = types.int;
      default = 262144;
      description = "The same limit in bytes.";
    };

    followHome = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Chase a home address that changed. Also lets anyone who can reach
        the control socket move the forwarder, so leave it off unless
        home's address really does change.
      '';
    };

    reportSeconds = mkOption {
      type = types.int;
      default = 60;
      description = "Seconds between count lines in the journal. 0 for none.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra arguments appended to the geist-forwardd command line.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.silentSeconds > cfg.pingSeconds;
        message = "services.geist-forward: silentSeconds must be longer than pingSeconds.";
      }
    ];

    networking.firewall.allowedUDPPorts =
      lib.mkIf cfg.openFirewall [ cfg.listenPort ];

    systemd.services.geist-forwardd = {
      description = "Geist datagram forwarder";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        ExecStart = "${cfg.package}/bin/geist-forwardd ${lib.escapeShellArgs forwardArgs}";
        Restart = "on-failure";
        RestartSec = 2;

        # It moves bytes and touches no file: the sandbox can be tight.
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
