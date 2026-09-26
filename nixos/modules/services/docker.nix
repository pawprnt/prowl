{ config, pkgs, ... }:

{
  virtualisation.docker = {
    enable = false;
    autoPrune.enable = true;
    enableOnBoot = false;
  };
}
