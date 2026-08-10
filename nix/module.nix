# ---------------------------------------------------------------------
# NixOS module <- geistd as a service, and geist as a client
# ---------------------------------------------------------------------
#
#   services.geistd = {
#     enable = true;
#     path = "/var/lib/geist/notes";
#     listenHost = "192.168.50.10";
#     identityFile = "/var/lib/geist/geistd.id";
#     trust = [ ./peers/laptop.pin ];        # may read
#     allowWrite = [ ./peers/desktop.pin ];  # may read AND send rows
#   };
#
# WHAT A PEER MAY DO COMES FROM THE OPTION IT IS LISTED UNDER, not from
# anything it sends. `trust` grants reads; `allowWrite` also grants writes
# and therefore makes the daemon take the store's write lease, so a direct
# `geist put` on the same machine is refused while it runs. That is the
# single-writer rule, not a limitation of the service.
#
# PINS ARE PUBLIC and are passed as plain paths: a pin is the half of an
# identity you are meant to hand out. SECRETS -- the at-rest password and
# the identity password -- go through systemd credentials instead, so they
# are never copied into the world-readable Nix store.
#
# THE IDENTITY FILE MUST PERSIST. A daemon that mints a fresh key on every
# start can never be pinned by anybody, so it lives in stateDir and is
# created on first start, not built.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.geistd;
  clientCfg = config.programs.geist-client;
  tomlFormat = pkgs.formats.toml { };

  hasSettings = settings: settings != { };

  configFileFor = name: c:
    if c.configFile != null then c.configFile
    else tomlFormat.generate "geist-${name}.toml" c.settings;

  usesConfigFile = c: c.configFile != null || hasSettings c.settings;

  listenArg = "dac://${cfg.listenHost}:${toString cfg.listenPort}";

  # Repeatable flags: one per pin, in the order the operator wrote them.
  pinArgs = flag: paths:
    lib.concatMap (p: [ flag (toString p) ]) paths;

  daemonArgs =
    [ "--path" cfg.path "--listen" listenArg "--preset" cfg.preset ]
    ++ [ "--subject" cfg.subject "--identity" cfg.identityFile ]
    ++ [ "--timeout-ms" (toString cfg.timeoutMs) ]
    ++ [ "--idle-seconds" (toString cfg.idleSeconds) ]
    ++ lib.optionals (cfg.maxRequests > 0) [ "--max-requests" (toString cfg.maxRequests) ]
    ++ lib.optional cfg.quiet "--quiet"
    ++ lib.optionals (usesConfigFile cfg) [ "--config" (toString (configFileFor "geistd" cfg)) ]
    ++ pinArgs "--trust" cfg.trust
    ++ pinArgs "--allow-write" cfg.allowWrite
    ++ cfg.extraArgs;

  # Secrets are resolved at RUN time from the credentials directory, which
  # is why this is a script and not a plain ExecStart argument list: the
  # path does not exist until systemd has made it.
  startScript = pkgs.writeShellScript "geistd-start" ''
    set -eu
    args=()
    if [ -n "''${CREDENTIALS_DIRECTORY:-}" ] && [ -f "$CREDENTIALS_DIRECTORY/db-password" ]; then
      args+=(--password-file "$CREDENTIALS_DIRECTORY/db-password")
    fi
    if [ -n "''${CREDENTIALS_DIRECTORY:-}" ] && [ -f "$CREDENTIALS_DIRECTORY/identity-password" ]; then
      args+=(--identity-password-file "$CREDENTIALS_DIRECTORY/identity-password")
    fi
    exec ${cfg.package}/bin/geistd ${
      lib.escapeShellArgs daemonArgs
    } "''${args[@]}"
  '';

  mkClientProfile = { name, ... }: {
    options = with lib; {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Generate this Geist client config.";
      };

      mode = mkOption {
        type = types.enum [ "merge" "replace" ];
        default = "merge";
        description = ''
          Whether this profile merges into the global client settings or
          replaces them outright.
        '';
      };

      target = mkOption {
        type = types.str;
        default = "geist/clients/${name}.toml";
        description = "Path below /etc for this profile's userconfig.toml.";
      };

      settings = mkOption {
        type = tomlFormat.type;
        default = { };
        description = "userconfig.toml contents for this profile.";
      };

      configFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "External config file. Mutually exclusive with settings.";
      };
    };
  };

  profileSettings = p:
    if p.mode == "replace" then p.settings
    else lib.recursiveUpdate clientCfg.settings p.settings;
in
{
  options.services.geistd = with lib; {
    enable = mkEnableOption "the Geist database daemon";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./default.nix { };
      defaultText = literalExpression "pkgs.callPackage ./default.nix { }";
      description = "Package providing geistd and geist.";
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/geist";
      description = ''
        Working directory, and where the identity file and any database
        created by the daemon live.
      '';
    };

    path = mkOption {
      type = types.str;
      default = "/var/lib/geist/main";
      description = ''
        The store root served: a DIRECTORY holding the artifact set, the
        generation manifest and the sidecar folder. Not a single file.
      '';
    };

    preset = mkOption {
      type = types.str;
      default = "app";
      description = ''
        Configuration preset the session opens with, as listed by
        `geist presets`. An encrypted preset needs passwordFile.
      '';
    };

    listenHost = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = ''
        Address to bind. The default keeps the daemon on this machine;
        serving other desktops means naming the interface address.
      '';
    };

    listenPort = mkOption {
      type = types.port;
      default = 47655;
      description = "UDP port to bind. DAC is a datagram protocol.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open listenPort (UDP) in the NixOS firewall.";
    };

    subject = mkOption {
      type = types.str;
      default = "geistd";
      description = "This daemon's identity subject, as peers will see it.";
    };

    identityFile = mkOption {
      type = types.str;
      default = "/var/lib/geist/geistd.id";
      description = ''
        This daemon's signing identity, created on first start. It must be
        a path that PERSISTS: peers pin the public half, and a daemon that
        minted a new key on every start could never be pinned.

        A string rather than a path, because it is written to at runtime
        and so cannot live in the Nix store.
      '';
    };

    passwordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        File holding the at-rest password, required by an encrypted
        preset. Loaded through systemd credentials, so it is readable only
        by the service and never copied into the Nix store.
      '';
    };

    identityPasswordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        File holding the password that seals the identity's secret keys.
        Falls back to passwordFile when unset; keeping them separate is
        better, since they protect different things.
      '';
    };

    trust = mkOption {
      type = types.listOf types.path;
      default = [ ];
      example = literalExpression ''[ ./peers/laptop.pin ]'';
      description = ''
        Peer pins allowed to READ. Pins are public, so these may be store
        paths. Exchanging the .pin files out of band IS the trust decision.
      '';
    };

    allowWrite = mkOption {
      type = types.listOf types.path;
      default = [ ];
      description = ''
        Peer pins allowed to read AND send rows. Any entry here makes the
        daemon take the store's write lease, so a direct `geist put` on
        this machine is refused while the service runs.
      '';
    };

    timeoutMs = mkOption {
      type = types.int;
      default = 1000;
      description = ''
        Socket poll window. This is a wakeup interval, not a request
        deadline: a short value costs one wakeup and keeps shutdown
        responsive.
      '';
    };

    idleSeconds = mkOption {
      type = types.int;
      default = 900;
      description = "Drop a peer session that has been silent this long.";
    };

    maxRequests = mkOption {
      type = types.int;
      default = 0;
      description = "Stop after this many requests. 0 means serve forever.";
    };

    quiet = mkOption {
      type = types.bool;
      default = false;
      description = "Suppress per-request logging.";
    };

    settings = mkOption {
      type = tomlFormat.type;
      default = { };
      description = ''
        userconfig.toml handed to the daemon with --config. Everything
        here also has a command line option, and the options this module
        passes explicitly always win, so this is for settings the module
        does not expose.
      '';
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "External userconfig.toml. Mutually exclusive with settings.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra arguments appended to the geistd command line.";
    };

    user = mkOption {
      type = types.str;
      default = "geist";
      description = "User account running geistd.";
    };

    group = mkOption {
      type = types.str;
      default = "geist";
      description = "Group running geistd.";
    };
  };

  options.programs.geist-client = with lib; {
    enable = mkEnableOption "the Geist command line client";

    package = mkOption {
      type = types.package;
      default = cfg.package;
      defaultText = literalExpression "config.services.geistd.package";
      description = "Package providing the geist CLI.";
    };

    installPackage = mkOption {
      type = types.bool;
      default = true;
      description = "Add the package to environment.systemPackages.";
    };

    target = mkOption {
      type = types.str;
      default = "geist/userconfig.toml";
      description = ''
        Path below /etc for the global client config.

        The CLI looks in the working directory and then in
        ~/.config/geist, NOT in /etc, so reach this one with
        `geist --config /etc/geist/userconfig.toml` or symlink it into a
        user's config directory. Keys are validated on load: an
        unrecognised one is an error rather than being ignored.
      '';
    };

    settings = mkOption {
      type = tomlFormat.type;
      default = { };
      example = literalExpression ''
        {
          database.path = "/var/lib/geist/notes";
          client = {
            remote = "dac://192.168.50.10:47655";
            peerPin = "/var/lib/geist/peers/server.pin";
          };
        }
      '';
      description = "userconfig.toml contents installed system-wide.";
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "External config file. Mutually exclusive with settings.";
    };

    profiles = mkOption {
      type = types.attrsOf (types.submodule mkClientProfile);
      default = { };
      description = "Additional named client configs below /etc.";
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = !(cfg.configFile != null && hasSettings cfg.settings);
          message = "services.geistd: configFile and settings are mutually exclusive.";
        }
        {
          # geistd refuses to start without one, and it is right to: with no
          # pin there is no peer to trust and every handshake would fail.
          assertion = cfg.trust != [ ] || cfg.allowWrite != [ ];
          message = ''
            services.geistd needs at least one peer pin in `trust` or
            `allowWrite`. Without one there is nobody to serve: every
            handshake would be refused.
          '';
        }
        {
          assertion = cfg.identityFile != "";
          message = "services.geistd.identityFile is required so peers can pin this daemon.";
        }
        {
          assertion = !(lib.hasPrefix builtins.storeDir cfg.identityFile);
          message = ''
            services.geistd.identityFile must be a writable path such as
            one below stateDir. The daemon creates it on first start, and
            the Nix store is read-only.
          '';
        }
      ];

      users.users = lib.mkIf (cfg.user == "geist") {
        geist = {
          isSystemUser = true;
          group = cfg.group;
          home = cfg.stateDir;
          createHome = true;
        };
      };

      users.groups = lib.mkIf (cfg.group == "geist") { geist = { }; };

      environment.etc = lib.mkIf (usesConfigFile cfg) {
        "geist/geistd.toml".source = configFileFor "geistd" cfg;
      };

      networking.firewall.allowedUDPPorts =
        lib.mkIf cfg.openFirewall [ cfg.listenPort ];

      systemd.tmpfiles.rules = [
        "d ${cfg.stateDir} 0750 ${cfg.user} ${cfg.group} - -"
      ];

      systemd.services.geistd = {
        description = "Geist database daemon";
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "simple";
          User = cfg.user;
          Group = cfg.group;
          WorkingDirectory = cfg.stateDir;
          ExecStart = startScript;
          LoadCredential =
            lib.optional (cfg.passwordFile != null)
              "db-password:${toString cfg.passwordFile}"
            ++ lib.optional (cfg.identityPasswordFile != null)
              "identity-password:${toString cfg.identityPasswordFile}";
          Restart = "on-failure";
          RestartSec = 2;

          # The daemon reads and writes one directory, talks over UDP, and
          # needs nothing else.
          NoNewPrivileges = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          ReadWritePaths = [ cfg.stateDir ];
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        };
      };
    })

    (lib.mkIf clientCfg.enable {
      assertions =
        [{
          assertion = !(clientCfg.configFile != null && hasSettings clientCfg.settings);
          message = "programs.geist-client: configFile and settings are mutually exclusive.";
        }]
        ++ lib.mapAttrsToList (name: p: {
          assertion = !(p.configFile != null && hasSettings p.settings);
          message = "programs.geist-client.profiles.${name}: configFile and settings are mutually exclusive.";
        }) clientCfg.profiles;

      environment.systemPackages =
        lib.mkIf clientCfg.installPackage [ clientCfg.package ];

      environment.etc =
        (lib.optionalAttrs (usesConfigFile clientCfg) {
          "${clientCfg.target}".source = configFileFor "client" clientCfg;
        })
        // lib.mapAttrs'
          (name: p: lib.nameValuePair p.target {
            source =
              if p.configFile != null then p.configFile
              else tomlFormat.generate "geist-client-${name}.toml"
                (profileSettings p);
          })
          (lib.filterAttrs (_: p: p.enable) clientCfg.profiles);
    })
  ];
}
