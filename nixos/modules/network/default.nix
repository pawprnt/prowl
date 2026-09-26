{ config, pkgs, lib, ... }:

{
  imports = [
    ./firewall.nix
    ./wifi.nix
  ];

  networking.hostName = "prowl-vm";
  networking.useDHCP = false;
  networking.networkmanager.enable = false;
}
