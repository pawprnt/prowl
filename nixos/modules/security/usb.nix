{ config, pkgs, ... }:

{
  environment.systemPackages = with pkgs; [ zenity yad ];

  services.udev.extraRules = ''
    ACTION=="add", SUBSYSTEM=="usb", RUN+="${pkgs.bash}/bin/bash -c '${pkgs.coreutils}/bin/echo add > /tmp/usb-approval'"
  '';

  systemd.services.usb-approval = {
    description = "USB device approval prompt";
    after = [ "multi-user.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = pkgs.writeScript "usb-approval" ''
        #!/bin/sh
        FIFO="/tmp/usb-approval"
        mkfifo "$FIFO" 2>/dev/null || true

        while true; do
          if read -r event < "$FIFO"; then
            USBDEV=$(lsblk -no NAME /dev/sd? 2>/dev/null | tail -1)
            if [ -n "$USBDEV" ]; then
              VENDOR=$(cat /sys/block/$USBDEV/device/vendor 2>/dev/null | xargs)
              MODEL=$(cat /sys/block/$USBDEV/device/model 2>/dev/null | xargs)

              if command -v zenity &>/dev/null; then
                zenity --question --title="USB Device" \
                  --text="Device: /dev/$USBDEV\nVendor: $VENDOR\nModel: $MODEL\n\nAllow?" \
                  --ok-label="Allow" --cancel-label="Block" 2>/dev/null
                RESULT=$?
              elif command -v yad &>/dev/null; then
                yad --question --title="USB Device" \
                  --text="Device: /dev/$USBDEV\nVendor: $VENDOR\nModel: $MODEL" \
                  --button="Allow:0" --button="Block:1" 2>/dev/null
                RESULT=$?
              else
                echo "USB: /dev/$USBDEV ($VENDOR $MODEL) [y/N]"
                read -r ans
                [ "$ans" = "y" ] && RESULT=0 || RESULT=1
              fi

              if [ $RESULT -eq 0 ]; then
                logger "USB allowed: /dev/$USBDEV ($VENDOR $MODEL)"
              else
                logger "USB blocked: /dev/$USBDEV ($VENDOR $MODEL)"
              fi
            fi
          fi
          sleep 1
        done
      '';
      Restart = "always";
      RestartSec = 5;
    };
  };
}
