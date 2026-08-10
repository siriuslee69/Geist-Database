# ---------------------------------------------------------------------
# NixOS module <- geist-relayd, the daemon with no database
# ---------------------------------------------------------------------
#
#   services.geist-relay = {
#     enable = true;
#     listenHost = "192.168.50.10";
#     identityFile = "/var/lib/geist-relay/relay.id";
#     allowWrite = [ ./peers/phone.pin ];   # may SEND messages
#     trust = [ ./peers/laptop.pin ];       # may COLLECT them
#     to = "exec";
#     exec = "${pkgs.whisper-cpp}/bin/whisper-cpp -";
#   };
#
# Same trust model as services.geistd, because it is the same handshake:
# peers are pinned, and the option a pin is listed under decides what that
# peer may do. What differs is where a message goes -- a command, a log
# file, or a queue somebody collects -- and that nothing is stored.
#
# `to = "exec"` RUNS A COMMAND AS THIS SERVICE, once per message. The
# message arrives on the command's stdin and never on its command line, so
# a peer cannot turn a message into a shell; but the command itself runs
# with whatever this unit can reach. Keep the sandbox below in mind when
# choosing one, and give it its own user if it needs more.
#
# THE IDENTITY FILE MUST PERSIST, for the same reason it must for geistd:
# a relay that mints a fresh key on every start can never be pinned.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.geist-relay;
  tomlFormat = pkgs.formats.toml { };

  hasSettings = settings: settings != { };

  configFile =
    if cfg.configFile != null then cfg.configFile
    else tomlFormat.generate "geist-relay.toml" cfg.settings;

  usesConfigFile = cfg.configFile != null || hasSettings cfg.settings;

  listenArg = "dac://${cfg.listenHost}:${toString cfg.listenPort}";

  pinArgs = flag: paths:
    lib.concatMap (p: [ flag (toString p) ]) paths;

  relayArgs =
    [ "--listen" listenArg "--subject" cfg.subject ]
    ++ [ "--identity" cfg.identityFile ]
    ++ [ "--to" cfg.to "--format" cfg.format ]
    ++ lib.optionals (cfg.file != null) [ "--file" (toString cfg.file) ]
    ++ lib.optionals (cfg.exec != null) [ "--exec" cfg.exec ]
    ++ [ "--exec-timeout-ms" (toString cfg.execTimeoutMs) ]
    ++ [ "--spool" (toString cfg.spool) ]
    ++ lib.concatMap (s: [ "--stream" s ]) cfg.streams
    ++ [ "--timeout-ms" (toString cfg.timeoutMs) ]
    ++ [ "--idle-seconds" (toString cfg.idleSeconds) ]
    ++ lib.optionals (cfg.maxRequests > 0) [ "--max-requests" (toString cfg.maxRequests) ]
    ++ lib.optional cfg.quiet "--quiet"
    ++ lib.optionals usesConfigFile [ "--config" (toString configFile) ]
    ++ pinArgs "--trust" cfg.trust
    ++ pinArgs "--allow-write" cfg.allowWrite
    ++ cfg.extraArgs;

  # The identity password is resolved at RUN time from the credentials
  # directory, which does not exist until systemd has made it.
  startScript = pkgs.writeShellScript "geist-relayd-start" ''
    set -eu
    args=()
    if [ -n "''${CREDENTIALS_DIRECTORY:-}" ] && [ -f "$CREDENTIALS_DIRECTORY/identity-password" ]; then
      args+=(--identity-password-file "$CREDENTIALS_DIRECTORY/identity-password")
    fi
    exec ${cfg.package}/bin/geist-relayd ${
      lib.escapeShellArgs relayArgs
    } "''${args[@]}"
  '';
in
{
  options.services.geist-relay = with lib; {
    enable = mkEnableOption "the Geist message relay";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./default.nix { };
      defaultText = literalExpression "pkgs.callPackage ./default.nix { }";
      description = "Package providing geist-relayd and geist-relay.";
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/geist-relay";
      description = ''
        Working directory, where the identity file lives and where a log
        written with `to = "file"` may go.
      '';
    };

    listenHost = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = ''
        Address to bind. The default keeps the relay on this machine;
        taking messages from a phone means naming the interface address.
      '';
    };

    listenPort = mkOption {
      type = types.port;
      default = 47656;
      description = ''
        UDP port to bind. One above geistd's, so a machine can run both.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open listenPort (UDP) in the NixOS firewall.";
    };

    subject = mkOption {
      type = types.str;
      default = "geist-relay";
      description = "This relay's identity subject, as peers will see it.";
    };

    identityFile = mkOption {
      type = types.str;
      default = "/var/lib/geist-relay/relay.id";
      description = ''
        This relay's signing identity, created on first start. It must be
        a path that PERSISTS: peers pin the public half.
      '';
    };

    identityPasswordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        File holding the password that seals the identity's secret keys.
        Loaded through systemd credentials, so it is readable only by the
        service and never copied into the Nix store.
      '';
    };

    trust = mkOption {
      type = types.listOf types.path;
      default = [ ];
      description = ''
        Peer pins allowed to COLLECT messages the relay is holding. Pins
        are public, so these may be store paths.
      '';
    };

    allowWrite = mkOption {
      type = types.listOf types.path;
      default = [ ];
      example = literalExpression ''[ ./peers/phone.pin ]'';
      description = ''
        Peer pins allowed to SEND messages. With `to = "exec"` this is
        also the list of peers whose messages start a command, so it is
        the option to be careful with.
      '';
    };

    to = mkOption {
      type = types.enum [ "spool" "stdout" "file" "exec" ];
      default = "spool";
      description = ''
        Where an accepted message goes.

        spool   held in memory for a peer to collect
        stdout  the unit's standard output, which is the journal
        file    appended to `file`
        exec    handed to `exec` on stdin; its output is the reply
      '';
    };

    format = mkOption {
      type = types.enum [ "lines" "json" "raw" ];
      default = "lines";
      description = ''
        How a message is written for the stdout and file sinks. `json` is
        one object per line; `raw` is the bytes with nothing added.
      '';
    };

    file = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Log to append to, required by `to = "file"`. A string rather than
        a path: it is written at runtime, so it cannot be in the store.
      '';
    };

    exec = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = literalExpression ''"''${pkgs.whisper-cpp}/bin/whisper-cpp -"'';
      description = ''
        Command run for each message, required by `to = "exec"`. The
        message arrives on its STDIN -- never on its command line -- and
        what it writes to stdout is sent back to whoever sent the message.
        `GEIST_STREAM`, `GEIST_FROM`, `GEIST_AT` and `GEIST_BYTES` are set
        in its environment.
      '';
    };

    execTimeoutMs = mkOption {
      type = types.int;
      default = 30000;
      description = ''
        How long that command may run before it is stopped. Generous by
        default, because transcription is not quick. 0 starts the command
        and does not wait for it, which is the fire-and-forget trigger.
      '';
    };

    streams = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = literalExpression ''[ "voice" "notes" ]'';
      description = ''
        Accept only these stream names. Empty accepts any, which is fine
        for a spool and worth narrowing when the sink is a command.
      '';
    };

    spool = mkOption {
      type = types.int;
      default = 256;
      description = ''
        Messages held per stream, in memory, for peers to collect. The
        oldest is dropped when the queue is full and the drop is counted;
        0 keeps nothing. Nothing here survives a restart -- a message that
        must is a job for services.geistd.
      '';
    };

    timeoutMs = mkOption {
      type = types.int;
      default = 1000;
      description = "Socket poll window, not a request deadline.";
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
        A userconfig.toml handed to the relay with --config, for settings
        this module does not expose. Its `[relay]` section is the one that
        applies. Options passed explicitly by this module always win.
      '';
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "External config file. Mutually exclusive with settings.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra arguments appended to the geist-relayd command line.";
    };

    readWritePaths = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Extra paths the unit may write to. stateDir is always included;
        this is for a command run by `exec` that needs somewhere else.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "geist-relay";
      description = "User account running geist-relayd.";
    };

    group = mkOption {
      type = types.str;
      default = "geist-relay";
      description = "Group running geist-relayd.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.configFile != null && hasSettings cfg.settings);
        message = "services.geist-relay: configFile and settings are mutually exclusive.";
      }
      {
        assertion = cfg.trust != [ ] || cfg.allowWrite != [ ];
        message = ''
          services.geist-relay needs at least one peer pin in `trust` or
          `allowWrite`. Without one there is nobody to talk to: every
          handshake would be refused.
        '';
      }
      {
        assertion = cfg.to != "exec" || cfg.exec != null;
        message = "services.geist-relay.to = \"exec\" needs `exec` set.";
      }
      {
        assertion = cfg.to != "file" || cfg.file != null;
        message = "services.geist-relay.to = \"file\" needs `file` set.";
      }
      {
        assertion = !(lib.hasPrefix builtins.storeDir cfg.identityFile);
        message = ''
          services.geist-relay.identityFile must be a writable path such
          as one below stateDir. The relay creates it on first start, and
          the Nix store is read-only.
        '';
      }
    ];

    users.users = lib.mkIf (cfg.user == "geist-relay") {
      geist-relay = {
        isSystemUser = true;
        group = cfg.group;
        home = cfg.stateDir;
        createHome = true;
      };
    };

    users.groups = lib.mkIf (cfg.group == "geist-relay") { geist-relay = { }; };

    environment.etc = lib.mkIf usesConfigFile {
      "geist/relay.toml".source = configFile;
    };

    networking.firewall.allowedUDPPorts =
      lib.mkIf cfg.openFirewall [ cfg.listenPort ];

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0750 ${cfg.user} ${cfg.group} - -"
    ];

    systemd.services.geist-relayd = {
      description = "Geist message relay";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        WorkingDirectory = cfg.stateDir;
        ExecStart = startScript;
        LoadCredential =
          lib.optional (cfg.identityPasswordFile != null)
            "identity-password:${toString cfg.identityPasswordFile}";
        Restart = "on-failure";
        RestartSec = 2;

        # A relay reads and writes its own directory, talks over UDP, and
        # -- with `to = "exec"` -- runs one command. The sandbox applies
        # to that command too, which is deliberate: it is the reason this
        # unit is not allowed to reach the rest of the system.
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ReadWritePaths = [ cfg.stateDir ] ++ cfg.readWritePaths;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
