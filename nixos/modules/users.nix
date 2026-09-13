{ config, pkgs, ... }:

{
  users.users.prowl = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" "docker" ];
    shell = pkgs.bash;
    home = "/home/prowl";
  };

  users.mutableUsers = true;
  users.users.root.initialPassword = "root";

  security.sudo.wheelNeedsPassword = false;
}
