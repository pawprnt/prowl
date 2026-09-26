{ config, pkgs, ... }:

{
  environment.systemPackages = with pkgs; [
    prowl
    git
    curl
    wget
    jq
    yq
    file
    unzip
    p7zip
    tmux
    screen
    netcat-gnu
    socat
    sshpass
    pciutils
    usbutils
    lsof
    strace
    ltrace
    ripgrep
    xxd
    hexdump
    xmlstarlet
    binutils
  ];
}
