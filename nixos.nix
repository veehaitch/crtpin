{ config, pkgs, lib, ... }:
with pkgs;
with lib;
let
  name = "crtpin";
  cfg = config.services.crtpin;
  user = name;
  group = name;
  host = toString cfg.host;
  port = toString cfg.port;
  allowRebind = if cfg.allowRebind then "true" else "false";
  crtpin = (callPackage ./default.nix { }).http;
in
{
  options.services."${name}" = with types; {
    enable = mkEnableOption "${name} service";
    host = mkOption {
      type = str;
      default = "::1";
      description = "Listening address.";
    };
    port = mkOption {
      type = ints.positive;
      default = 8000;
      description = "Listening port.";
    };
    allowRebind = mkOption {
      type = bool;
      default = true;
      description = "Whether to filter requests which resolve to private IPv4/IPv6 ranges.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services."${name}-service" = {
      description = "${name} - process";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        User = user;
        Group = group;
        WorkingDirectory = "${crtpin}";
        ExecStart = ''${crtpin}/bin/crtpin-http \
          -host="${host}" \
          -port=${port} \
          -allow-rebind=${allowRebind}
        '';

        Restart = "on-failure";

        IPAccounting = true;

        # Security
        IPAddressDeny = lib.concatStringsSep " " [
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

        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallFilter = lib.concatStringsSep " " [
          "@system-service"
          "~@mount"
        ];
        SystemCallErrorNumber = "EPERM";
      };
    };

    users.users.${user} = {
      group = group;
      isSystemUser = true;
    };
    users.groups = {
      "${group}" = { };
    };
  };
}
