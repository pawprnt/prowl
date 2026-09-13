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
    # USB HID (badusb prevention)
    "usbhid"
    "usbkbd"
    "usbmouse"
    "hid-generic"
    "hid-apple"
    "hid-logitech"
    "hid-microsoft"
  ];

  # Disable USB storage and HID via udev
  services.udev.extraRules = ''
    # Block USB storage devices
    ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", RUN+="/bin/false"
    # Block USB HID devices (keyboard/mouse emulators)
    ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}=="03", RUN+="/bin/false"
    # Block composite devices with HID interfaces
    ACTION=="add", SUBSYSTEM=="usb", ATTR{bNumInterfaces}=="*", ENV{INTERFACE}=="*/3/*", RUN+="/bin/false"
  '';

  # Disable core dumps
  systemd.coredump.enable = false;
  security.pam.loginLimits = [
    { domain = "*"; type = "hard"; item = "core"; value = "0"; }
  ];
}
