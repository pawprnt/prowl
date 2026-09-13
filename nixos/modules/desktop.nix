{ config, pkgs, ... }:

{
  services.xserver = {
    enable = true;
    desktopManager.xfce.enable = true;
    displayManager.lightdm.enable = true;
  };

  services.displayManager.autoLogin = {
    enable = true;
    user = "prowl";
  };
}
