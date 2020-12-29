{
  pkgs ? import <nixpkgs> {},
  lib ? pkgs.lib,
  buildGoModule ? pkgs.buildGoModule
}:
let 
  base = name: buildGoModule rec {
    pname = name;
    version = "0.0.1";

    src = lib.cleanSource ./.;
    vendorSha256 = "1qzkrrik2hv8z1z55xig9wkdi2hz6nsd2ch582jnjdwj83lrjf8z";

    doCheck = false;

    subPackages = [ "cmd/${name}" ];

    meta = with lib; {
      description = "Crtpin (${name}) is a tiny program to calculate public key hashes of hosts suitable for certificate pinning";
      homepage = "https://github.com/veehaitch/crtpin";
      license = licenses.asl20;
      maintainers = with maintainers; [ veehaitch ];
      platforms = platforms.all;
    };
  };
in {
  http = base "crtpin-http";
  cli = base "crtpin-cli";
}
