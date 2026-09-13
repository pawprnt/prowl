{
  description = "Prowl Security Research VM";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pawprnt-pkgs = {
      url = "github:pawprnt/nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixos-generators, pawprnt-pkgs, ... }: {
    packages.x86_64-linux.prowl-kali = nixos-generators.nixosGenerate {
      system = "x86_64-linux";
      format = "vm";
      modules = [
        ./configuration.nix
        ({ pkgs, ... }: {
          nixpkgs.overlays = [ pawprnt-pkgs.overlays.default ];
        })
      ];
    };

    packages.x86_64-linux.default = self.packages.x86_64-linux.prowl-kali;
  };
}
