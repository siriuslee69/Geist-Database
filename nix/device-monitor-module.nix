# Two Geist API consumers, with separate identities, databases and debug logs.
{ config, lib, ... }:
let
  cfg = config.services.geistDeviceMonitor;
  daemon = mode: port: {
    description = "Geist device monitor ${mode} (AM1P+S / DAC)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "simple";
      User = cfg.user;
      ExecStart = "${lib.escapeShellArg cfg.executable} ${lib.escapeShellArg (cfg.dataDir + "/" + mode)} ${mode} dac://0.0.0.0:${toString port}";
      Restart = "on-failure";
      RestartSec = 3;
      UMask = "0077";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ (cfg.dataDir + "/" + mode) ];
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      LimitCORE = 0;
      StandardOutput = "append:${cfg.dataDir}/${mode}/service.log";
      StandardError = "append:${cfg.dataDir}/${mode}/service.log";
    };
  };
in {
  options.services.geistDeviceMonitor = {
    enable = lib.mkEnableOption "the two Geist device monitor daemons";
    user = lib.mkOption { type = lib.types.str; description = "Account owning the provisioned keys."; };
    executable = lib.mkOption { type = lib.types.str; description = "Absolute path to the tested geist-monitord executable."; };
    dataDir = lib.mkOption { type = lib.types.str; description = "Private root with relay/ and store/ provisioned through Geist."; };
    relayPort = lib.mkOption { type = lib.types.port; default = 47656; };
    storePort = lib.mkOption { type = lib.types.port; default = 47655; };
  };
  config = lib.mkIf cfg.enable {
    networking.firewall.allowedUDPPorts = [ cfg.relayPort cfg.storePort ];
    systemd.services.geist-device-relay = daemon "relay" cfg.relayPort;
    systemd.services.geist-device-store = daemon "store" cfg.storePort;
  };
}
