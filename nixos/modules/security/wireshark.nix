{ config, pkgs, ... }:

{
  # Wireshark group for capture permissions
  users.groups.wireshark = {};

  # Add prowl to wireshark group
  users.users.prowl.extraGroups = [ "wireshark" ];
}
