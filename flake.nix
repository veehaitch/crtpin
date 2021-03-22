{
  description = "Program to generate hashes suitable for certificate pinning";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          name = "crtpin";
          pkgs = import nixpkgs { inherit system; };
          crtpin = pkgs.callPackage ./default.nix { };
        in
        rec {
          packages.crtpin-cli = crtpin.cli;
          packages.crtpin-http = crtpin.http;

          defaultPackage = self.packages.${system}.crtpin-cli;

          devShell = import ./shell.nix { inherit pkgs; };
        })
    //
    {
      overlay = final: prev: {
        inherit (self.packages.${final.system}) crtpin-cli crtpin-http;
      };

      nixosModules.crtpin-http =
        { ... }:
        {
          nixpkgs.overlays = [ self.overlay ];
          imports = [ ./module.nix ];
        };
    };
}
