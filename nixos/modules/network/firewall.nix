{ config, lib, ... }:

{
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 8080 8081 ];
    allowedUDPPorts = [ 53 ];
    allowedTCPPortRanges = [ ];
    logRefusedConnections = true;
    rejectPackets = true;
  };
  networking.nftables.enable = true;
}
