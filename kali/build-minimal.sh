#!/usr/bin/env bash
#
# Build a minimal Kali Linux QEMU image with debootstrap.
# Only installs exactly what's needed — no metapackages.
#
# Usage: ./build-minimal.sh [-s SIZE] [-U USER:PASS] [-D DESKTOP] [-- <debootstrap args>]
#

set -eu

ARCH=amd64
SIZE=30
USERPASS=kali:kali
DESKTOP=xfce
MIRROR=http://http.kali.org/kali
BRANCH=kali-rolling
OUTPUT=build/images
KEEP=false

while getopts ":s:U:D:m:b:kh" opt; do
    case $opt in
        s) SIZE=$OPTARG ;;
        U) USERPASS=$OPTARG ;;
        D) DESKTOP=$OPTARG ;;
        m) MIRROR=$OPTARG ;;
        b) BRANCH=$OPTARG ;;
        k) KEEP=true ;;
        h) echo "Usage: $0 [-s SIZE] [-U USER:PASS] [-D DESKTOP] [-m MIRROR] [-b BRANCH] [-k]"; exit 0 ;;
        *) echo "Invalid option: -$OPTARG" 1>&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

USERNAME=$(echo "$USERPASS" | cut -d: -f1)
PASSWORD=$(echo "$USERPASS" | cut -d: -f2-)

ROOTFS=$(mktemp -d /tmp/prowl-rootfs.XXXXXX)
SCRATCH=$(mktemp -d /tmp/prowl-scratch.XXXXXX)
trap 'sudo umount "$ROOTFS"/dev/pts 2>/dev/null; sudo umount "$ROOTFS"/dev 2>/dev/null; sudo umount "$ROOTFS"/proc 2>/dev/null; sudo umount "$ROOTFS"/sys 2>/dev/null; sudo rm -rf "$ROOTFS" "$SCRATCH"' EXIT

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Prowl Minimal Kali Image Builder"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Architecture:  $ARCH"
echo " Desktop:        $DESKTOP"
echo " User:           $USERNAME"
echo " Disk size:      ${SIZE}GB"
echo " Rootfs temp:    $ROOTFS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Debootstrap minimal rootfs ──────────────────────
echo ""
echo "▶ Step 1/7: Debootstrap minimal rootfs..."
sudo debootstrap --arch="$ARCH" --variant=minbase \
    "$BRANCH" "$ROOTFS" "$MIRROR"

# ── 2. Configure APT repos ─────────────────────────────
echo ""
echo "▶ Step 2/7: Configuring Kali repos..."
sudo tee "$ROOTFS/etc/apt/sources.list" > /dev/null <<EOF
deb $MIRROR $BRANCH main contrib non-free non-free-firmware
deb-src $MIRROR $BRANCH main contrib non-free non-free-firmware
EOF

# Import Kali keyring
sudo chroot "$ROOTFS" bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        kali-archive-keyring \
        kali-linux-keyring
'

# ── 3. System packages (kernel, init, networking) ──────
echo ""
echo "▶ Step 3/7: Installing system packages..."
sudo chroot "$ROOTFS" bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    # Core system
    apt-get install -y --no-install-recommends \
        linux-image-amd64 \
        systemd \
        systemd-sysv \
        init \
        dbus \
        udev \
        kmod \
        procps \
        locales \
        sudo \
        su \
        passwd \
        login \
        coreutils \
        util-linux \
        mount \
        less \
        nano \
        vim-tiny \
        bash-completion

    # Networking
    apt-get install -y --no-install-recommends \
        ifupdown \
        iproute2 \
        iputils-ping \
        net-tools \
        openssh-client \
        openssh-server \
        network-manager \
        wireless-tools \
        wpasupplicant \
        curl \
        wget

    # Essential utils
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gnupg \
        software-properties-common \
        apt-transport-https \
        git \
        jq \
        file \
        unzip \
        p7zip-full \
        netcat-openbsd \
        socat \
        sshpass \
        tmux \
        screen

    # Cleanup
    apt-get clean
    rm -rf /var/lib/apt/lists/*
'

# ── 4. Desktop environment ─────────────────────────────
echo ""
echo "▶ Step 4/7: Installing desktop ($DESKTOP)..."

install_xfce() {
    sudo chroot "$ROOTFS" bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            xfce4 \
            xfce4-terminal \
            xfce4-notifyd \
            xfce4-power-manager \
            lightdm \
            lightdm-gtk-greeter \
            dbus-x11 \
            xserver-xorg \
            xinit \
            x11-xserver-utils \
            xdg-utils \
            fonts-dejavu \
            fonts-liberation \
            papirus-icon-theme \
            network-manager-gnome
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    '
}

install_kde() {
    sudo chroot "$ROOTFS" bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            plasma-desktop \
            plasma-workspace \
            sddm \
            konsole \
            dolphin \
            kate \
            spectacle \
            ark \
            dolphin-plugins \
            kde-cli-tools \
            plasma-nm \
            plasma-pa \
            plasma-framework \
            bluedevil \
            powerdevil \
            sddm-theme-breeze \
            dbus-x11 \
            xserver-xorg \
            x11-xserver-utils \
            xdg-utils \
            fonts-dejavu \
            fonts-liberation \
            papirus-icon-theme \
            network-manager-gnome
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    '
}

case "$DESKTOP" in
    xfce)  install_xfce ;;
    kde)   install_kde ;;
    none)  echo "  Skipping desktop" ;;
    *)     echo "Unknown desktop: $DESKTOP"; exit 1 ;;
esac

# ── 5. Security tools (exact packages, no metapackages) ─
echo ""
echo "▶ Step 5/7: Installing security tools..."
sudo chroot "$ROOTFS" bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    # Network scanning
    apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        hping3 \
        arping

    # Web testing
    apt-get install -y --no-install-recommends \
        nikto \
        whatweb \
        sqlmap \
        testssl.sh \
        dirb \
        wfuzz

    # Password attacks
    apt-get install -y --no-install-recommends \
        hydra \
        john \
        hashcat \
        cewl \
        crunch \
        medusa

    # Exploitation
    apt-get install -y --no-install-recommends \
        metasploit-framework

    # Post-exploitation / recon
    apt-get install -y --no-install-recommends \
        responder \
        bloodhound \
        enum4linux \
        smbclient \
        ldap-utils

    # Forensics / RE
    apt-get install -y --no-install-recommends \
        binwalk \
        foremost \
        strings \
        radare2 \
        ltrace \
        strace

    # MITM / Sniffing
    apt-get install -y --no-install-recommends \
        bettercap \
        mitmproxy \
        tcpdump \
        tshark \
        dsniff

    # Wireless
    apt-get install -y --no-install-recommends \
        aircrack-ng \
        reaver \
        bully \
        pixiewps

    # Utilities
    apt-get install -y --no-install-recommends \
        docker.io \
        docker-compose \
        golang-go \
        python3 \
        python3-pip \
        python3-venv \
        ruby \
        perl \
        nikto \
        sslscan

    # Cleanup
    apt-get clean
    rm -rf /var/lib/apt/lists/*
'

# ── 6. System configuration ────────────────────────────
echo ""
echo "▶ Step 6/7: Configuring system..."

# Set hostname
sudo chroot "$ROOTFS" bash -c 'echo "prowl-kali" > /etc/hostname'

# Set timezone
sudo chroot "$ROOTFS" bash -c 'ln -sf /usr/share/zoneinfo/America/Chicago /etc/localtime'

# Enable services
sudo chroot "$ROOTFS" bash -c '
    systemctl enable ssh
    systemctl enable NetworkManager
    systemctl enable lightdm 2>/dev/null || systemctl enable sddm 2>/dev/null || true
'

# Create user
sudo chroot "$ROOTFS" bash -c "
    useradd -m -s /bin/bash -G sudo,docker $USERNAME
    echo '$USERNAME:$PASSWORD' | chpasswd
    echo 'root:$PASSWORD' | chpasswd
    echo '$USERNAME ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/$USERNAME
"

# Clean up
sudo chroot "$ROOTFS" bash -c '
    apt-get clean
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
    truncate -s 0 /var/log/*.log 2>/dev/null || true
    truncate -s 0 /var/log/**/*.log 2>/dev/null || true
'

# ── 7. Create disk image ──────────────────────────────
echo ""
echo "▶ Step 7/7: Creating disk image..."

mkdir -p "$OUTPUT"

# Create raw disk image
RAW="$SCRATCH/prowl-kali.raw"
dd if=/dev/zero of="$RAW" bs=1M count=$((SIZE * 1024)) status=progress

# Partition (MBR, single partition)
echo -e "o\nn\np\n1\n\n\nw" | sudo fdisk "$RAW" || true

# Setup loop device with partition scan
LOOP=$(sudo losetup -fP --show "$RAW")
PART="${LOOP}p1"

# Format
sudo mkfs.ext4 -q "$PART"

# Mount and copy rootfs
sudo mkdir -p /mnt/rootfs
sudo mount "$PART" /mnt/rootfs
echo "Copying rootfs to disk..."
sudo rsync -a "$ROOTFS/" /mnt/rootfs/

# Generate fstab
UUID=$(sudo blkid -s UUID -o value "$PART")
sudo tee /mnt/rootfs/etc/fstab > /dev/null <<EOF
UUID=$UUID   /   ext4   defaults,noatime   0 1
EOF

# Install bootloader
sudo chroot /mnt/rootfs bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends grub-pc
    grub-install --target=i386-pc '"$LOOP"' || true
    update-grub
'

# Cleanup mount
sudo umount /mnt/rootfs
sudo losetup -d "$LOOP"

# Convert to qcow2
echo "Converting to qcow2..."
qemu-img convert -f raw -O qcow2 "$RAW" "$OUTPUT/prowl-kali.qcow2"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Build complete!"
echo " Image: $OUTPUT/prowl-kali.qcow2"
echo " Size:  $(du -h "$OUTPUT/prowl-kali.qcow2" | cut -f1)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
