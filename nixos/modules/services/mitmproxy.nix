{ config, pkgs, ... }:

let
  urlFile = "/home/prowl/.mitmweb-url";
  proxyPort = 8080;
  webPort = 8081;
  certDir = "/home/prowl/.mitmproxy";

  certSetupScript = pkgs.writeShellScript "mitmproxy-setup-cert" ''
    #!/bin/sh
    mkdir -p "${certDir}"
    # Copy fixed certs if not already present
    if [ ! -f "${certDir}/mitmproxy-ca.pem" ]; then
      ${pkgs.coreutils}/bin/cp ${../../data/mitmproxy-certs/mitmproxy-ca.pem} "${certDir}/mitmproxy-ca.pem"
      ${pkgs.coreutils}/bin/chmod 600 "${certDir}/mitmproxy-ca.pem"
    fi
    if [ ! -f "${certDir}/mitmproxy-ca-cert.pem" ]; then
      ${pkgs.coreutils}/bin/cp ${../../data/mitmproxy-certs/mitmproxy-ca-cert.pem} "${certDir}/mitmproxy-ca-cert.pem"
    fi
  '';
in
{
  # ── Trust mitmproxy CA system-wide ────────────────────
  security.pki.certificateFiles = [
    ../../data/mitmproxy-certs/mitmproxy-ca-cert.pem
  ];

  # ── MiTM Proxy Service ────────────────────────────────
  systemd.services.mitmproxy = {
    description = "mitmproxy web interface";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      User = "prowl";
      Group = "prowl";
      ExecStartPre = [
        "${pkgs.coreutils}/bin/rm -f ${urlFile}"
        "${certSetupScript}"
        "${pkgs.iptables}/bin/iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
      ];
      ExecStart = pkgs.writeShellScript "mitmweb-start" ''
        #!/bin/sh
        export HOME=/home/prowl
        export XDG_RUNTIME_DIR=/run/user/$(id -u)

        ${pkgs.mitmproxy}/bin/mitmweb \
          --mode transparent \
          --showhost \
          --listen-host 0.0.0.0 \
          --listen-port ${toString proxyPort} \
          --web-port ${toString webPort} \
          --set console_open=false \
          2>&1 | while IFS= read -r line; do
            echo "$line"
            URL=$(echo "$line" | ${pkgs.gnugrep}/bin/grep -oP 'Web server listening at \Khttp://.*' || true)
            if [ -n "$URL" ]; then
              echo "$URL" > ${urlFile}
              ${pkgs.coreutils}/bin/chmod 600 ${urlFile}
              echo "URL saved to ${urlFile}"
            fi
          done
      '';
      ExecStopPost = [
        "${pkgs.iptables}/bin/iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 80 -j REDIRECT --to-port ${toString proxyPort}"
        "${pkgs.iptables}/bin/ip6tables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner prowl --dport 443 -j REDIRECT --to-port ${toString proxyPort}"
      ];
      Restart = "on-failure";
      RestartSec = 5;
    };
  };

  # ── LibreWolf with Dark Reader ────────────────────────
  programs.firefox = {
    enable = true;
    package = pkgs.librewolf;
    policies = {
      ExtensionSettings = {
        "addon@darkreader.org" = {
          install_url = "https://addons.mozilla.org/firefox/downloads/latest/darkreader/latest.xpi";
          installation_mode = "force_installed";
        };
      };
    };
  };

  # ── Desktop Entry ─────────────────────────────────────
  environment.etc."xdg/applications/mitmweb.desktop" = {
    text = ''
      [Desktop Entry]
      Name=mitmweb
      Comment=mitmproxy Web Interface
      Exec=${pkgs.writeShellScript "mitmweb-launch" ''
        URL_FILE="${urlFile}"
        DEFAULT_URL="http://127.0.0.1:${toString webPort}"

        if [ -f "$URL_FILE" ]; then
          URL=$(${pkgs.coreutils}/bin/cat "$URL_FILE")
        else
          URL="$DEFAULT_URL"
        fi

        ${pkgs.librewolf}/bin/librewolf "$URL"
      ''}
      Type=Application
      Terminal=false
      Categories=Network;Security;
      Keywords=mitmproxy;proxy;security;
    '';
  };
}
