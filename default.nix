{
  pkgs ? import <nixpkgs> {},
  lib ? pkgs.lib,
  buildGoModule ? pkgs.buildGoModule
}:

buildGoModule rec {
  pname = "crtpin-cli";
  version = "0.0.1";

  src = lib.cleanSource ./.;
  vendorSha256 = "1qzkrrik2hv8z1z55xig9wkdi2hz6nsd2ch582jnjdwj83lrjf8z";

  doCheck = false;

  subPackages = [
    "cmd/crtpin-cli"
    "cmd/crtpin-http"
  ];

  meta = with lib; {
    description = "Crtpin is a tiny program to calculate public key hashes of hosts suitable for certificate pinning";
    homepage = "https://github.com/veehaitch/crtpin";
    license = licenses.asl20;
    maintainers = with maintainers; [ veehaitch ];
    platforms = platforms.all;
  };
}
