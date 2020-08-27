with import <nixpkgs> {};

mkShell {
  name = "crtpin-shell";
  buildInputs = [ 
    go
    golint
  ];

  shellHook = ''
    export GO111MODULE="auto"

    export GOPATH=$(realpath ${toString ./.}/go)
    mkdir -p $GOPATH/{bin,src}

    export GOBIN=$GOPATH/bin
  '';
}
