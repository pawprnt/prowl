{ config, pkgs, lib, ... }:

{
  boot.loader.grub = {
    device = "/dev/sda";
    configurationLimit = 5;
    users.prowl.hashedPassword = "\$6\$abcdefghij\$P1Xl2Y1cfgHH/aXNwejbpfpBl88V8bi5WP6ezYA.m/ihubZKpE5kXfLSDrp1Tl6j5RgY0sHNAfs1I0T1O2qxU/";
  };
}
