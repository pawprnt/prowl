{ config, pkgs, lib, ... }:

{
  imports = [
    ./hardware-configuration.nix
  ];

  # ── Boot ──────────────────────────────────────────────
  boot.loader.grub.device = "/dev/sda";
  boot.loader.grub.configurationLimit = 5;

  # ── Kernel hardening ──────────────────────────────────
  boot.kernel.sysctl = {
    # Network hardening
    "net.ipv4.ip_forward" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.conf.default.accept_source_route" = 0;
    "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
    "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv4.tcp_timestamps" = 0;

    # IPv6 hardening
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.default.accept_source_route" = 0;

    # Kernel hardening
    "kernel.randomize_va_space" = 2;
    "kernel.kptr_restrict" = 2;
    "kernel.dmesg_restrict" = 1;
    "kernel.yama.ptrace_scope" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
    "kernel.unprivileged_userns_clone" = 0;
    "net.core.bpf_jit_harden" = 2;
    "fs.protected_hardlinks" = 1;
    "fs.protected_symlinks" = 1;
    "fs.suid_dumpable" = 0;
  };

  boot.kernelParams = [
    "slab_nomerge"
    "init_on_alloc=1"
    "init_on_free=1"
    "page_alloc.shuffle=1"
  ];

  boot.blacklistedKernelModules = [
    "cramfs"
    "freevxfs"
    "hfs"
    "hfsplus"
    "jffs2"
    "udf"
  ];

  # ── System ────────────────────────────────────────────
  system.stateVersion = "24.11";

  networking.hostName = "prowl-kali";
  networking.useDHCP = true;
  networking.networkmanager.enable = true;

  time.timeZone = "America/Chicago";

  i18n.defaultLocale = "en_US.UTF-8";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "en_US.UTF-8";
    LC_IDENTIFICATION = "en_US.UTF-8";
    LC_MEASUREMENT = "en_US.UTF-8";
    LC_MONETARY = "en_US.UTF-8";
    LC_NAME = "en_US.UTF-8";
    LC_NUMERIC = "en_US.UTF-8";
    LC_PAPER = "en_US.UTF-8";
    LC_TELEPHONE = "en_US.UTF-8";
    LC_TIME = "en_US.UTF-8";
  };

  # ── Firewall ──────────────────────────────────────────
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 8080 8081 ];
    allowedUDPPorts = [ 53 ];
    allowedTCPPortRanges = [
      { from = 1024; to = 65535; } # tool ports
    ];
    logRefusedConnections = true;
    rejectPackets = true;
  };

  # ── Users ─────────────────────────────────────────────
  users.users.kali = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" "docker" ];
    shell = pkgs.bash;
  };

  users.mutableUsers = false;
  users.users.kali.initialPassword = "kali";

  # ── SSH (hardened) ────────────────────────────────────
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = true;
      X11Forwarding = false;
      MaxAuthTries = 3;
      ClientAliveInterval = 300;
      ClientAliveCountMax = 2;
      AllowUsers = [ "kali" ];
    };
  };

  # ── mitmproxy (auto-start, routes all traffic) ───────
  services.mitmproxy = {
    enable = true;
    port = 8080;
    webPort = 8081;
    verbose = false;
  };

  # System-wide proxy via NetworkManager
  environment.sessionVariables = {
    HTTP_PROXY = "http://127.0.0.1:8080";
    HTTPS_PROXY = "http://127.0.0.1:8080";
    http_proxy = "http://127.0.0.1:8080";
    https_proxy = "http://127.0.0.1:8080";
    ALL_PROXY = "socks5://127.0.0.1:8080";
    no_proxy = "localhost,127.0.0.1,::1";
  };

  # ── Desktop (XFCE) ────────────────────────────────────
  services.xserver = {
    enable = true;
    desktopManager.xfce.enable = true;
    displayManager.lightdm.enable = true;
  };

  services.displayManager.autoLogin = {
    enable = true;
    user = "kali";
  };

  # ── Packages ──────────────────────────────────────────
  environment.systemPackages = with pkgs; [
    # Prowl
    prowl

    # Core utilities
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

    # Network scanning
    nmap
    masscan
    hping3
    arping

    # Web testing
    nikto
    whatweb
    sqlmap
    testssl
    dirb
    wfuzz
    ffuf

    # Password attacks
    hydra
    john
    hashcat
    cewl
    crunch
    medusa

    # Post-exploitation / recon
    enum4linux
    smbclient
    ldap-utils

    # Forensics / RE
    binwalk
    foremost
    radare2
    sslscan

    # MITM / Sniffing
    bettercap
    mitmproxy
    mitmweb
    tcpdump
    tshark
    dsniff

    # Wireless
    aircrack-ng

    # Languages
    python3
    python3Packages.pip
    ruby
    go
    perl

    # Docker
    docker
    docker-compose
  ];

  # ── Docker ────────────────────────────────────────────
  virtualisation.docker = {
    enable = true;
    autoPrune.enable = true;
  };

  # ── Security ──────────────────────────────────────────
  security.sudo.wheelNeedsPassword = false;

  # ── Nix settings ──────────────────────────────────────
  nix = {
    settings = {
      experimental-features = [ "nix-command" "flakes" ];
      auto-optimise-store = true;
    };
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 7d";
    };
  };
}
