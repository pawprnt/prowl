{ config, pkgs, ... }:

{
  nixpkgs.overlays = [
    (final: prev: {
      prowl = prev.prowl.overrideAttrs (old: {
        src = final.fetchurl {
          url = "https://github.com/pawprnt/prowl/archive/v1.0.0.tar.gz";
          hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        };
      });
    })
  ];
}
