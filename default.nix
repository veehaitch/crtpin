{ pkgs ? import <nixpkgs> { }
, lib ? pkgs.lib
, buildGoModule ? pkgs.buildGoModule
}:
let
  base = name: buildGoModule {
    pname = name;
    version = "0.0.1";

    src = lib.cleanSource ./.;
    vendorHash = "sha256-HzmZ6UCSN2mlQAUy0bQ1H4rYJk8v9lJ++GhDMWPO8+M=";

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
in
{
  http = base "crtpin-http";
  cli = base "crtpin-cli";
}
