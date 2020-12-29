{
  pkgs ? import <nixpkgs> {},
  lib ? pkgs.lib,
  buildGoModule ? pkgs.buildGoModule
}:

buildGoModule rec {
  pname = "crtpin";
  version = "0.0.1";

  src = lib.cleanSource ./.;
  vendorSha256 = "16bmlirhy7a3hgga75xbk63mcar891ivgj58pbh6cj2nmqszvzpr";

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
