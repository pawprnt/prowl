{ config, pkgs, lib, ... }:

{
  boot.kernelModules = [ "virtio_blk" "virtio_net" "virtio_pci" "virtio_scsi" ];
  boot.blacklistedKernelModules = [ "firewire_core" "firewire_ohci" "ieee1394" "yenta_socket" "pcmcia_core" ];

  services.getty.autologinUser = null;
  services.rpcbind.enable = false;
  services.avahi.enable = false;
  hardware.bluetooth.enable = false;
  networking.wireless.enable = false;

  security.tpm2.enable = false;

  system.activationScripts.postUserActivation.text = ''
    ${pkgs.systemd}/bin/systemctl set-default multi-user.target
  '';
}
