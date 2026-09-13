{ config, ... }:

{
  environment.persistence."/persist" = {
    directories = [
      "/etc/nixos"
      "/var/lib/mitmproxy"
      "/var/lib/docker"
      "/var/log"
      "/var/lib/networkmanager"
    ];
    files = [
      "/etc/machine-id"
    ];
  };

  environment.persistence."/persist/home" = {
    users = {
      prowl = {
        directories = [
          ".config/prowl"
          ".ssh"
          ".local"
          ".cache"
          "Documents"
          "Downloads"
        ];
        files = [
          ".bash_history"
        ];
      };
    };
  };
}
