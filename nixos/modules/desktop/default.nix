{ config, pkgs, ... }:

{
  imports = [
    ./display.nix
    ./audio.nix
    ./gpu.nix
    ./power.nix
  ];
}
