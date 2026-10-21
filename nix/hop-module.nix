# ---------------------------------------------------------------------
# NixOS module <- geist-hopd, the router machines link to
# ---------------------------------------------------------------------
#
#   services.geist-hop = {
#     enable = true;
#     openFirewall = true;
#     routeId = 16;
#     peers = [
#       { pin = ./peers/phone.pin; id = 48; }
#       { pin = ./peers/nas.pin;   id = 32; }
#       { pin = ./peers/office-hop.pin; id = 17; router = true;
#         endpoint = "dac://office.example:47658"; }
#     ];
#     targets = [
#       { id = 32; name = "nas"; visibleTo = [ "phone" ]; }
#       { id = 33; name = "cam"; visibleTo = [ "phone" ]; via = 17; }
#     ];
#   };
#
# Each neighbour makes one handshake with this router; through it they
# reach the targets they may see, end to end. The router holds the LINK
# keys, never the end-to-end ones: it sees who talks to whom and how much,
# not what (docs/hop.md). Its identity lives in the state directory.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.geist-hop;
  tomlFormat = pkgs.formats.toml { };

  hopToml = tomlFormat.generate "geist-hop.toml" {
    listen = "dac://${cfg.listenHost}:${toString cfg.listenPort}";
    subject = cfg.subject;
    id = cfg.routeId;
    identity = "${cfg.stateDir}/hop.id";
    identityPasswordFile = "";
    timeoutMs = cfg.timeoutMs;
    idleSeconds = cfg.idleSeconds;
    quiet = cfg.quiet;
    peer = map (p: {
      pin = toString p.pin;
      id = p.id;
      router = p.router;
      endpoint = p.endpoint;
    }) cfg.peers;
    target = map (t: {
      id = t.id;
      name = t.name;
      visibleTo = t.visibleTo;
      via = t.via;
    }) cfg.targets;
  };

  peerType = with lib; types.submodule {
    options = {
      pin = mkOption { type = types.path; description = "The neighbour's pin (public)."; };
      id = mkOption { type = types.ints.positive; description = "The route id this router gives it."; };
      router = mkOption { type = types.bool; default = false; description = "Another geist-hopd: its origin ids are believed."; };
      endpoint = mkOption { type = types.str; default = ""; description = "For a router this one DIALS: dac://host:port."; };
    };
  };

  targetType = with lib; types.submodule {
    options = {
      id = mkOption { type = types.ints.positive; description = "Route id clients address."; };
      name = mkOption { type = types.str; description = "Name shown in the directory (at most 32 bytes)."; };
      visibleTo = mkOption { type = types.listOf types.str; description = "Pin SUBJECTS that may see and reach it; \"*\" for everyone."; };
      via = mkOption { type = types.ints.unsigned; default = 0; description = "Route id of the router it sits behind; 0 = it links here."; };
    };
  };
in
{
  options.services.geist-hop = with lib; {
    enable = mkEnableOption "geist-hopd, the router Geist machines link to";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./default.nix { };
      defaultText = literalExpression "pkgs.callPackage ./default.nix { }";
      description = "Package providing geist-hopd.";
    };

    listenHost = mkOption { type = types.str; default = "0.0.0.0"; description = "Address neighbours dial."; };
    listenPort = mkOption { type = types.port; default = 47658; description = "UDP port (docs/ports.md)."; };
    openFirewall = mkOption { type = types.bool; default = false; description = "Open listenPort (UDP) in the NixOS firewall."; };
    subject = mkOption { type = types.str; default = "geist-hop"; description = "Name on this router's pin."; };
    routeId = mkOption { type = types.ints.positive; description = "This router's own route id."; };
    peers = mkOption { type = types.listOf peerType; default = [ ]; description = "Every neighbour allowed to link."; };
    targets = mkOption { type = types.listOf targetType; default = [ ]; description = "The directory."; };
    timeoutMs = mkOption { type = types.int; default = 2000; description = "Per dial of another router."; };
    idleSeconds = mkOption { type = types.int; default = 900; description = "A link silent this long is dropped."; };
    quiet = mkOption { type = types.bool; default = false; description = "No status lines in the journal."; };
    stateDir = mkOption { type = types.str; default = "/var/lib/geist-hop"; description = "Holds the router's identity."; };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.peers != [ ];
        message = "services.geist-hop: at least one peer; a router nobody may link to refuses every handshake.";
      }
    ];

    networking.firewall.allowedUDPPorts =
      lib.mkIf cfg.openFirewall [ cfg.listenPort ];

    systemd.services.geist-hopd = {
      description = "Geist hop router";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        StateDirectory = baseNameOf cfg.stateDir;
        ExecStart = "${cfg.package}/bin/geist-hopd --config ${hopToml}";
        Restart = "on-failure";
        RestartSec = 2;

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
