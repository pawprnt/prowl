{ config, pkgs, ... }:

{
  imports = [
    ./ssh.nix
    ./mitmproxy.nix
    ./docker.nix
    ./dotfiles.nix
  ];
}
