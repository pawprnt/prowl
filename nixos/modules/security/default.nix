{ config, pkgs, ... }:

{
  imports = [
    ./kernel.nix
    ./apparmor.nix
    ./usb.nix
  ];
}
