{ config, ... }:

{
  networking.hostName = "prowler";
  networking.useDHCP = true;
  networking.networkmanager.enable = true;

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 8080 8081 ];
    allowedUDPPorts = [ 53 ];
    allowedTCPPortRanges = [
      { from = 1024; to = 65535; }
    ];
    logRefusedConnections = true;
    rejectPackets = true;
  };
}
