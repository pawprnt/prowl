# Prowl NixOS Image

NixOS-based security research VM with prowl and tools pre-installed.

## Structure

```
nixos/
├── configuration.nix          # Main entry point
├── flake.nix                  # Build definitions
├── README.md
├── hosts/
│   ├── prowl/                 # Real hardware config
│   │   └── default.nix
│   └── vm/                    # VM config
│       └── default.nix
├── profiles/
│   └── base.nix               # Base system settings
├── modules/
│   ├── boot/                  # Bootloader
│   │   ├── default.nix
│   │   └── grub.nix
│   ├── desktop/               # GUI
│   │   ├── default.nix
│   │   ├── display.nix
│   │   ├── audio.nix
│   │   ├── gpu.nix
│   │   └── power.nix
│   ├── network/               # Networking
│   │   ├── default.nix
│   │   ├── firewall.nix
│   │   └── wifi.nix
│   ├── security/              # Hardening
│   │   ├── default.nix
│   │   ├── kernel.nix
│   │   ├── apparmor.nix
│   │   └── usb.nix
│   ├── services/              # System services
│   │   ├── default.nix
│   │   ├── ssh.nix
│   │   ├── mitmproxy.nix
│   │   ├── docker.nix
│   │   └── dotfiles.nix
│   ├── users/                 # User accounts
│   │   ├── default.nix
│   │   └── prowl.nix
│   ├── packages/              # Software
│   │   ├── default.nix
│   │   ├── core.nix
│   │   ├── security.nix
│   │   └── languages.nix
│   ├── nix/                   # Nix settings
│   │   ├── default.nix
│   │   └── store.nix
│   └── persistence/           # Impermanence
│       ├── default.nix
│       ├── system.nix
│       └── user.nix
├── hardware/
│   ├── generic.nix            # Real hardware
│   ├── vm.nix                 # QEMU guest
│   └── vm-hardening.nix       # VM-specific hardening
└── overlays/
    └── default.nix
```

## Building

### VM Image

```bash
cd nixos
nix build .#prowl-kali
```

### Real Hardware

```bash
sudo nixos-rebuild switch --flake .#prowl
```

## User

- **Username:** prowl
- **Password:** SSH key only (password auth disabled)
- **Groups:** wheel
- **GRUB password:** `prowl` (SHA-512 hashed)

## Hardening

### Kernel
- KASLR enabled (`kaslr`)
- PTI/KPTI on (`pti=on`)
- Spectre v2 mitigation (`spectre_v2=on`)
- L1TF full force (`l1tf=full,force`)
- MDS full nosmt (`mds=full,nosmt`)
- TSX disabled (`tsx=off`)
- SMT/hyperthreading disabled (`nosmt`)
- IOMMU passthrough (`iommu=pt`)
- `slab_nomerge`, `init_on_alloc=1`, `init_on_free=1`
- IP forwarding disabled
- IPv6 disabled
- `kptr_restrict=2`, `dmesg_restrict=1`
- `ptrace_scope=2`, `unprivileged_bpf_disabled=1`
- `unprivileged_userns_clone=0`
- `modules_disabled=1`, `kexec_load_disabled=1`
- `perf_event_paranoid=3`
- ICMP echo ignored, martians logged
- TCP SYN cookies, timestamps disabled

### Network
- nftables firewall enabled
- Only ports 22, 8080, 8081 TCP + 53 UDP open
- Port range 1024-65535 closed
- `rejectPackets = true` (REJECT not DROP)
- NetworkManager disabled
- WiFi disabled
- Avahi, RPC, Bluetooth disabled

### SSH
- PasswordAuthentication: **disabled**
- PermitRootLogin: **no**
- X11Forwarding: **disabled**
- MaxAuthTries: 3
- AllowTcpForwarding: **disabled**
- PermitUserEnvironment: **disabled**

### Boot
- GRUB password protected
- GRUB user `prowl` with SHA-512 hash
- configurationLimit: 5

### Desktop
- Auto-login: **disabled**
- Plasma6: **disabled** (headless)
- KVM guests only (virtio drivers)

### Services
- Docker: **disabled**
- polkit: managed by display manager
- usb-approval service blocks unknown USB devices

### Filesystem
- Impermanence (wipes /persist on reboot)
- `/var/lib/nixos` persisted (UID/GID stable)
- Docker storage removed from persistence

## Features

- **Reproducible** — declarative config
- **Hardened** — kernel, firewall, SSH, USB blocking, AppArmor
- **Impermanence** — wipes root on reboot
- **mitmproxy** — routes all traffic through proxy
- **Hardware-agnostic** — works on VM and real hardware
