{ config, pkgs, ... }:

{
  services.xserver = {
    enable = true;
    videoDrivers = [ "modesetting" ];
  };

  services.desktopManager.plasma6.enable = false;
  services.displayManager.autoLogin.enable = false;
}
