{ config, ... }:

{
  environment.persistence."/persist" = {
    directories = [
      "/etc/nixos"
      "/var/lib/mitmproxy"
      "/var/log"
      "/var/lib/networkmanager"
      "/var/lib/apparmor"
      "/var/lib/nixos"
    ];
    files = [
      "/etc/machine-id"
    ];
  };
}
