{ config, pkgs, ... }:

{
  networking.networkmanager.wifi.powersave = true;
  hardware.enableRedistributableFirmware = true;
}
