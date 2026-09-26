{ config, ... }:

{
  systemd.tmpfiles.rules = [
    "d /nix/store 0555 root root -"
    "d /nix/var   0755 root root -"
  ];
}
