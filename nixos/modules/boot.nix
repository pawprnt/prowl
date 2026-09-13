{ config, lib, pkgs, ... }:

{
  boot.loader.grub.device = "/dev/sda";
  boot.loader.grub.configurationLimit = 5;
}
