{
  description = "The tools needed for dev";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in
  {
    devShells.${system}.default = 
      pkgs.mkShell
        {
          buildInputs = [
            pkgs.cowsay
            pkgs.lolcat
            pkgs.cargo
          ];

          LC_ALL="C.UTF-8";

          shellHook = ''
            echo "${system}" | cowsay | lolcat
          '';
        };
  };
}
