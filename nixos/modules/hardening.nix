{ config, ... }:

{
  boot.kernel.sysctl = {
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

    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.default.accept_source_route" = 0;

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

  # USB approval prompt
  services.udev.extraRules = ''
    # Trigger USB approval dialog on device add
    ACTION=="add", SUBSYSTEM=="usb", RUN+="${pkgs.bash}/bin/bash -c '${pkgs.coreutils}/bin/echo add $$ > /tmp/usb-event'"
  '';

  systemd.services.usb-approval = {
    description = "USB device approval prompt";
    after = [ "multi-user.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = pkgs.writeScript "usb-approval-monitor" ''
        #!/bin/sh
        FIFO="/tmp/usb-approval"
        ${pkgs.coreutils}/bin/mkfifo "$FIFO" 2>/dev/null || true
        
        while true; do
          if read -r event < "$FIFO"; then
            DEVICES=$(${pkgs.util_linux}/bin/lsblk -no NAME,SIZE,MODEL /dev/sd? 2>/dev/null | tail -1)
            USBDEV=$(${pkgs.gnugrep}/bin/grep -l "ID_BUS=usb" /sys/block/sd*/uevent 2>/dev/null | head -1 | xargs dirname | xargs basename)
            
            if [ -n "$USBDEV" ]; then
              VENDOR=$(${pkgs.coreutils}/bin/cat /sys/block/$USBDEV/device/vendor 2>/dev/null | xargs)
              MODEL=$(${pkgs.coreutils}/bin/cat /sys/block/$USBDEV/device/model 2>/dev/null | xargs)
              
              ${pkgs.bash}/bin/bash -c "
                if command -v zenity &>/dev/null; then
                  zenity --question --title=\"USB Device Detected\" \
                    --text=\"A USB device was connected:\\n\\nDevice: /dev/$USBDEV\\nVendor: $VENDOR\\nModel: $MODEL\\n\\nAllow this device?\" \
                    --ok-label=\"Allow\" --cancel-label=\"Block\" 2>/dev/null
                  RESULT=\$?
                elif command -v yad &>/dev/null; then
                  yad --question --title=\"USB Device Detected\" \
                    --text=\"A USB device was connected:\\n\\nDevice: /dev/$USBDEV\\nVendor: $VENDOR\\nModel: $MODEL\\n\\nAllow this device?\" \
                    --button=\"Allow:0\" --button=\"Block:1\" 2>/dev/null
                  RESULT=\$?
                else
                  echo \"USB device detected: /dev/$USBDEV ($VENDOR $MODEL)\"
                  echo -n \"Allow? [y/N]: \"
                  read -r answer
                  if [ \"\$answer\" = \"y\" ] || [ \"\$answer\" = \"Y\" ]; then
                    RESULT=0
                  else
                    RESULT=1
                  fi
                fi
                
                if [ \$RESULT -eq 0 ]; then
                  logger \"USB approval: Allowed /dev/$USBDEV ($VENDOR $MODEL)\"
                  ${pkgs.util_linux}/bin/mount /dev/$USBDEV /mnt/usb 2>/dev/null || true
                else
                  logger \"USB approval: Blocked /dev/$USBDEV ($VENDOR $MODEL)\"
                  ${pkgs.coreutils}/bin/echo 0 > /sys/block/$USBDEV/device/enable 2>/dev/null || true
                fi
              "
            fi
          fi
          sleep 1
        done
      '';
      Restart = "always";
      RestartSec = 5;
    };
  };

  # Disable core dumps
  systemd.coredump.enable = false;
  security.pam.loginLimits = [
    { domain = "*"; type = "hard"; item = "core"; value = "0"; }
  ];
}
