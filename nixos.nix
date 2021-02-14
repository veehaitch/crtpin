{ config, pkgs, lib, ... }:
let
  name = "crtpin";
  cfg = config.services.crtpin;
  host = toString cfg.host;
  port = toString cfg.port;
  allowRebind = if cfg.allowRebind then "true" else "false";
  crtpin = (pkgs.callPackage ./default.nix { }).http;
in
{
  options.services."${name}" = with lib; {
    enable = mkEnableOption "${name} service";
    host = mkOption {
      type = types.str;
      default = "::1";
      description = "Listening address.";
    };
    port = mkOption {
      type = types.ints.positive;
      default = 8000;
      description = "Listening port.";
    };
    allowRebind = mkOption {
      type = types.bool;
      default = false;
      description = "Whether to filter requests which resolve to private IPv4/IPv6 ranges.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services."${name}" = {
      description = "${name} - certificate pinning service";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = ''${crtpin}/bin/crtpin-http \
            -host="${host}" \
            -port=${port} \
            -allow-rebind=${allowRebind}
        '';
        Restart = "on-failure";

        # Accounting
        CPUAccounting = true;
        IPAccounting = true;
        MemoryAccounting = true;

        # Security
        CapabilityBoundingSet = "";
        DynamicUser = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateMounts = true;
        PrivateTmp = true;
        PrivateUsers = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";

        # Needs network access
        IPAddressDeny = lib.optionals (cfg.allowRebind == false) [
          # deny private ipv4
          "10.0.0.0/8"
          "172.16.0.0/12"
          "192.168.0.0/16"
          # deny private ipv6
          "fd00::/8"
          "link-local"
          # deny multicast for ipv4/ipv6
          "multicast"
        ];
        SystemCallFilter = [ "@network-io" ];
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        PrivateNetwork = false;
      };
    };
  };
}
