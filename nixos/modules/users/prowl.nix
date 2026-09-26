{ config, pkgs, ... }:

{
  users.users.prowl = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    shell = pkgs.bash;
    home = "/home/prowl";
  };
}
