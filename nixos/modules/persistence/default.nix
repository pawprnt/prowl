{ config, pkgs, ... }:

{
  imports = [
    ./system.nix
    ./user.nix
  ];
}
