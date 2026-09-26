{ config, pkgs, ... }:

{
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
        fi
      '';
      ExecStop = pkgs.writeScript "unmount-dotfiles" ''
        #!/bin/sh
        umount /home/prowl/.dotfiles 2>/dev/null || true
      '';
    };
  };
}
