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
    impermanence.url = "github:nix-community/impermanence";
  };

  outputs = { self, nixpkgs, nixos-generators, pawprnt-pkgs, impermanence, ... }: {
      packages.x86_64-linux.prowl-kali = nixos-generators.nixosGenerate {
        system = "x86_64-linux";
        format = "vm";
        modules = [
          impermanence.nixosModules.impermanence
          ./configuration.nix
          ./hosts/vm
          ({ pkgs, ... }: {
            nixpkgs.overlays = [ pawprnt-pkgs.overlays.default ];
          })
        ];
      };

     packages.x86_64-linux.prowl-vm = self.packages.x86_64-linux.prowl-kali;

     packages.x86_64-linux.default = self.packages.x86_64-linux.prowl-vm;

     nixosConfigurations.prowl = nixpkgs.lib.nixosSystem {
       system = "x86_64-linux";
       modules = [
         impermanence.nixosModules.impermanence
         ./configuration.nix
         ./hosts/prowl
         ({ pkgs, ... }: {
           nixpkgs.overlays = [ pawprnt-pkgs.overlays.default ];
         })
       ];
     };
  };
}
