{ config, pkgs, lib, ... }:

{
  imports = [ ./prowl.nix ];

  users.mutableUsers = false;
  users.users.root.initialPassword = null;
  users.allowNoPasswordLogin = true;
  security.sudo.wheelNeedsPassword = true;
}
