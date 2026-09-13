{ config, pkgs, ... }:

{
  environment.systemPackages = with pkgs; [
    prowl
    git
    curl
    wget
    jq
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

    nmap
    masscan
    hping3
    arping

    nikto
    whatweb
    sqlmap
    testssl
    dirb
    wfuzz
    ffuf

    hydra
    john
    hashcat
    cewl
    crunch
    medusa

    enum4linux
    smbclient
    ldap-utils

    binwalk
    foremost
    radare2
    sslscan

    bettercap
    mitmproxy
    mitmweb
    tcpdump
    tshark
    dsniff

    aircrack-ng

    python3
    python3Packages.pip
    ruby
    go
    perl

    docker
    docker-compose

    (pkgs.writeShellScriptBin "dotfiles-rw" ''
      mount -o remount,bind,rw /home/prowl/.dotfiles
      echo ".dotfiles remounted read-write"
    '')
    (pkgs.writeShellScriptBin "dotfiles-ro" ''
      mount -o remount,bind,ro /home/prowl/.dotfiles
      echo ".dotfiles remounted read-only"
    '')
  ];
}
