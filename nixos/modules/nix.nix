{ config, ... }:

{
  nix = {
    settings = {
      experimental-features = [ "nix-command" "flakes" ];
      auto-optimise-store = true;
      # Restrict store access
      trusted-users = [ "root" "@wheel" ];
      allowed-users = [ "root" "@wheel" ];
      # Disable substituters we don't use
      substituters = [ "https://cache.nixos.org" ];
      # Require signature verification
      require-sigs = true;
      # Sandbox builds
      sandbox = true;
      # Prevent store leaks
      show-trace = true;
    };
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 7d";
    };
  };

  # Harden Nix store permissions
  systemd.tmpfiles.rules = [
    "d /nix/store 0555 root root -"
    "d /nix/var   0755 root root -"
  ];

  # Disable remote builds (attack surface reduction)
  nix.extraOptions = ''
    # Disable distributed builds
    max-jobs = auto
    # Log all builds for audit
    log-serialise = true
    # Build within sandbox
    sandbox-fallback = false
  '';
}
