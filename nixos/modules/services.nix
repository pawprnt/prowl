{ config, pkgs, ... }:

{
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = true;
      X11Forwarding = false;
      MaxAuthTries = 3;
      ClientAliveInterval = 300;
      ClientAliveCountMax = 2;
      AllowUsers = [ "prowl" ];
    };
  };

  services.mitmproxy = {
    enable = true;
    port = 8080;
    webPort = 8081;
    verbose = false;
  };

  environment.sessionVariables = {
    HTTP_PROXY = "http://127.0.0.1:8080";
    HTTPS_PROXY = "http://127.0.0.1:8080";
    http_proxy = "http://127.0.0.1:8080";
    https_proxy = "http://127.0.0.1:8080";
    ALL_PROXY = "socks5://127.0.0.1:8080";
    no_proxy = "localhost,127.0.0.1,::1";
  };

  systemd.services.mount-dotfiles = {
    description = "Mount .dotfiles as read-only";
    after = [ "local-fs.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = pkgs.writeScript "mount-dotfiles" ''
        #!/bin/sh
        DOTFILES="/home/prowl/.dotfiles"
        if [ -d "$DOTFILES" ]; then
          mount --bind "$DOTFILES" "$DOTFILES"
          mount -o remount,bind,ro "$DOTFILES"
          echo "Mounted .dotfiles as read-only"
        else
          echo "No .dotfiles found, skipping"
        fi
      '';
      ExecStop = pkgs.writeScript "unmount-dotfiles" ''
        #!/bin/sh
        umount /home/prowl/.dotfiles 2>/dev/null || true
      '';
    };
  };

  virtualisation.docker = {
    enable = true;
    autoPrune.enable = true;
  };
}
