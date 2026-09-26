{ config, pkgs, ... }:

{
  imports = [
    ./core.nix
    ./security.nix
    ./languages.nix
  ];
}
