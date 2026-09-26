{ config, pkgs, ... }:

{
  nixpkgs.overlays = [
    (final: prev: {
      # Add custom overlays here
    })
  ];
}
