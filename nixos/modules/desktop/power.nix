{ config, pkgs, ... }:

{
  services.thermald.enable = true;
  services.power-profiles-daemon.enable = true;
}
