{ config, pkgs, ... }:

{
  imports = [ ./store.nix ];

  nixpkgs.config.allowUnfreePredicate = pkg: builtins.elem (pkgs.lib.getName pkg) [
    "dumpifs"
    "waybackurls"
    "wpscan"
    "volatility3"
  ];

  nix = {
    settings = {
      experimental-features = [ "nix-command" "flakes" ];
      auto-optimise-store = true;
      trusted-users = [ "root" "@wheel" ];
      allowed-users = [ "root" "@wheel" ];
      substituters = [ "https://cache.nixos.org" ];
      require-sigs = true;
      sandbox = true;
    };
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 7d";
    };
    extraOptions = ''
      sandbox-fallback = false
      log-serialise = true
    '';
  };
}
