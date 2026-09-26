{ config, pkgs, lib, ... }:

{
  imports = [
    ./boot
    ./desktop
    ./network
    ./security
    ./services
    ./users
    ./packages
    ./nix
    ./persistence
  ];
}
