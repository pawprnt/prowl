#!/usr/bin/env just --list

binary_name := "build/prowl"
version := `git describe --tags --always 2>/dev/null || echo "dev"`
commit := `git rev-parse --short HEAD 2>/dev/null || echo "none"`
date := `date -u +%Y-%m-%dT%H:%M:%SZ`
output_name := "prowl-kali"
max_part_size := "1800M"
image_type := env_var_or_default("IMAGE_TYPE", "qemu")

# ─── Build ──────────────────────────────────────────────────

# Build for current platform (default)
default: build

build:
    CGO_ENABLED=0 go build -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" -tags netgo -installsuffix netgo -o {{binary_name}} ./cmd/prowl/

# Build with race detector (requires CGO)
build-race:
    go build -race -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" -o {{binary_name}}-race ./cmd/prowl/

# Cross-compile for linux/amd64
build-linux:
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" -tags netgo -installsuffix netgo -o {{binary_name}}-linux-amd64 ./cmd/prowl/

# Cross-compile for linux/arm64
build-linux-arm:
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" -tags netgo -installsuffix netgo -o {{binary_name}}-linux-arm64 ./cmd/prowl/

# Cross-compile for darwin/amd64
build-darwin:
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" -tags netgo -installsuffix netgo -o {{binary_name}}-darwin-amd64 ./cmd/prowl/

# Cross-compile for darwin/arm64 (Apple Silicon)
build-darwin-arm:
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" -tags netgo -installsuffix netgo -o {{binary_name}}-darwin-arm64 ./cmd/prowl/

# Cross-compile for windows/amd64
build-windows:
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" -tags netgo -installsuffix netgo -o {{binary_name}}-windows-amd64.exe ./cmd/prowl/

# Build all platforms
build-all: build-linux build-linux-arm build-darwin build-darwin-arm build-windows

# Run the binary
run: build
    ./{{binary_name}}

# ─── Install ────────────────────────────────────────────────

# Install to /usr/local/bin
install:
    @echo "Installing to /usr/local/bin (requires sudo)..."
    sudo cp {{binary_name}} /usr/local/bin/{{binary_name}}
    @echo "Installed {{binary_name}} to /usr/local/bin/"

# ─── Dev ────────────────────────────────────────────────────

# Run go mod tidy
tidy:
    go mod tidy

# Run all tests
test:
    go test ./... -v

# Run tests with coverage
test-cover:
    go test ./... -cover -coverprofile=coverage.out
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# Run benchmarks
bench:
    go test ./... -bench=. -benchmem

# Run go vet
vet:
    go vet ./...

# Format all code
fmt:
    gofmt -w .
    @echo "Formatted all .go files"

# Check formatting
fmt-check:
    @gofmt -l . | if read -r line; then echo "Unformatted files:"; gofmt -l .; exit 1; else echo "All files formatted"; fi

# Lint
lint:
    @which staticcheck >/dev/null 2>&1 && staticcheck ./... || (echo "staticcheck not installed, using go vet" && go vet ./...)

# Clean build artifacts
clean:
    rm -f {{binary_name}} {{binary_name}}-race {{binary_name}}-*-*
    rm -f coverage.out coverage.html
    @echo "Cleaned build artifacts"

# Show project stats
stats:
    @echo "=== Prowl Stats ==="
    @echo "Go files:  $(find . -name '*.go' | wc -l)"
    @echo "Total lines: $(find . -name '*.go' -exec cat {} + | wc -l)"
    @echo "Packages:  $(find . -name '*.go' -exec dirname {} + | sort -u | wc -l)"

# Check available security tools
check-tools:
    @echo "=== Security Tools ==="
    @for tool in nmap nuclei httpx subfinder ffuf whatweb sqlmap dalfox katana gau amass dirb nikto wpscan smbclient enum4linux hydra john hashcat sslscan curl wget openssl; do \
        if command -v $$tool >/dev/null 2>&1; then echo "  ✓ $$tool"; else echo "  ✗ $$tool"; fi; \
    done

# ─── Kali VM ────────────────────────────────────────────────

# SSH into Kali VM
kali:
    sshpass -p kali ssh -o StrictHostKeyChecking=no -p 9222 -t kali@127.0.0.1

# Deploy prowl to Kali VM
deploy-kali: build-linux
    sshpass -p kali scp -o StrictHostKeyChecking=no -P 9222 {{binary_name}}-linux-amd64 kali@127.0.0.1:~/
    sshpass -p kali ssh -o StrictHostKeyChecking=no -p 9222 kali@127.0.0.1 "chmod +x ~/prowl-linux-amd64"
    @echo "Deployed to Kali: ~/prowl-linux-amd64"

# Run prowl on Kali
run-kali: deploy-kali
    sshpass -p kali ssh -o StrictHostKeyChecking=no -p 9222 -t kali@127.0.0.1 "~/prowl-linux-amd64"

# ─── Bounty Data ────────────────────────────────────────────

# Init/update bounty data submodule
init-submodule:
    git submodule update --init --recursive

# Update bounty data
update-bounty-data:
    cd bounty-data && git pull origin main

# ─── Kali Image Build ──────────────────────────────────────

# Build prowl for Linux (prerequisite for image)
build-for-image:
    @echo "Building prowl for Linux amd64..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags "-s -w -X main.version={{version}} -X main.commit={{commit}} -X main.date={{date}}" \
        -tags netgo -installsuffix netgo \
        -o {{binary_name}}-linux-amd64 ./cmd/prowl/
    @echo "Built {{binary_name}}-linux-amd64"

# Build base Kali image from scratch using kali-vm
# Usage: just download-kali
#        IMAGE_TYPE=virtualbox just download-kali
download-kali:
    @echo "Building base Kali image (type: {{image_type}})..."
    @cd kali/image-build && sudo ./build.sh \
        -v {{image_type}} -f {{image_type}} -T none -s 40 -U kali:kali \
        -P "nmap masscan nikto whatweb sqlmap hydra john hashcat metasploit-framework burpsuite responder bloodhound binwalk radare2 bettercap mitmproxy semgrep curl wget git docker.io jq sshpass testssl" \
        -- --artifactdir ../../build/images
    @echo "Ready: build/images/"

# Download previous release (for incremental builds)
download-prev-release:
    @echo "Checking for previous release..."
    @mkdir -p releases
    @if [ -f "releases/manifest.json" ]; then \
        echo "Found previous release manifest"; \
        PARTS=$$(ls releases/{{output_name}}.part.* 2>/dev/null | wc -l); \
        echo "Found $$PARTS parts"; \
        if [ "$$PARTS" -gt 0 ]; then \
            echo "Reassembling previous release..."; \
            cat releases/{{output_name}}.part.* > releases/{{output_name}}.qcow2; \
            echo "Reassembled: releases/{{output_name}}.qcow2"; \
        fi; \
    else \
        echo "No previous release found, will build from scratch"; \
    fi

# Create work image (copy-on-write from base)
create-work-image:
    @echo "Creating work image..."
    @mkdir -p build
    @if [ -f "releases/{{output_name}}.qcow2" ]; then \
        echo "Using previous release as base (incremental)..."; \
        qemu-img create -f qcow2 -b "releases/{{output_name}}.qcow2" -F qcow2 "build/{{output_name}}-work.qcow2"; \
    else \
        echo "Using base Kali image (full build)..."; \
        BASE=$$(ls build/images/*.qcow2 2>/dev/null | head -1); \
        qemu-img create -f qcow2 -b "$$BASE" -F qcow2 "build/{{output_name}}-work.qcow2"; \
    fi
    @qemu-img resize "build/{{output_name}}-work.qcow2" 40G
    @echo "Work image ready"

# Clean image caches (smaller image)
clean-image-caches:
    @echo "Cleaning caches and unnecessary files from image..."
    @virt-customize -a "build/{{output_name}}-work.qcow2" \
        --run-command "apt-get clean" \
        --run-command "apt-get autoremove -y" \
        --run-command "rm -rf /var/cache/apt/archives/* /var/lib/apt/lists/*" \
        --run-command "rm -rf /tmp/* /var/tmp/*" \
        --run-command "rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/info/*" \
        --run-command "rm -rf /usr/share/locale/* /usr/share/i18n/*" \
        --run-command "rm -rf /var/cache/pip/* /root/.cache/*" \
        --run-command "rm -rf /var/log/*.log /var/log/**/*.log" \
        --run-command "find / -name '*.pyc' -delete 2>/dev/null || true" \
        --run-command "find / -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true" \
        2>&1 | grep -v "^$" || true
    @echo "Caches cleaned"

# Install prowl into image
install-prowl-image: build-for-image
    @echo "Installing prowl into image..."
    @virt-customize -a "build/{{output_name}}-work.qcow2" \
        --upload "{{binary_name}}-linux-amd64:/usr/local/bin/prowl" \
        --run-command "chmod +x /usr/local/bin/prowl" \
        2>&1 | grep -v "^$" || true
    @echo "prowl installed in image"

# Bundle bounty-data into image
bundle-bounty-data:
    @echo "Bundling bounty-data into image..."
    @virt-customize -a "build/{{output_name}}-work.qcow2" \
        --run-command "mkdir -p /home/kali/.prowl" \
        --upload "bounty-data:/home/kali/.prowl/bounty-data" \
        --run-command "chown -R kali:kali /home/kali/.prowl" \
        2>&1 | grep -v "^$" || true
    @echo "bounty-data bundled"

# Install Kali tools into image (full metapackage install)
install-tools-image:
    @echo "Installing Kali tools into image..."
    @virt-customize -a "build/{{output_name}}-work.qcow2" \
        --run-command "DEBIAN_FRONTEND=noninteractive apt-get update" \
        --run-command "DEBIAN_FRONTEND=noninteractive apt-get install -y kali-tools-web kali-tools-passwords kali-tools-exploitation kali-tools-post-exploitation kali-tools-forensics kali-tools-sniffing-spoofing kali-tools-information-gathering kali-tools-vulnerability kali-tools-social-engineering kali-tools-reverse-engineering kali-tools-wireless kali-tools-fuzzing kali-tools-database kali-tools-hardware kali-tools-crypto-stego" \
        --run-command "apt-get clean" \
        2>&1 | grep -v "^$" || true
    @echo "Tools installed"

# Sparsify and compress image
compress-image:
    @echo "Sparsifying and compressing image..."
    @mkdir -p build
    @virt-sparsify --compress "build/{{output_name}}-work.qcow2" "build/{{output_name}}-sparse.qcow2" 2>/dev/null || \
        cp "build/{{output_name}}-work.qcow2" "build/{{output_name}}-sparse.qcow2"
    @qemu-img convert -f qcow2 -O qcow2 -c \
        -o compression_type=zlib,cluster_size=65536 \
        "build/{{output_name}}-sparse.qcow2" "{{output_name}}.qcow2" 2>/dev/null || \
        cp "build/{{output_name}}-sparse.qcow2" "{{output_name}}.qcow2"
    @echo "Final size: $$(du -h {{output_name}}.qcow2 | cut -f1)"

# Split image for GitHub release (2GB limit)
split-image:
    @echo "Splitting image into {{max_part_size}} parts..."
    @mkdir -p splits
    @rm -f splits/*
    @split -b {{max_part_size}} -d -a 3 "{{output_name}}.qcow2" "splits/{{output_name}}.part."
    @PARTS=$$(ls splits/*.part.* | wc -l); \
    SIZE=$$(du -sh splits | cut -f1); \
    echo "Split into $$PARTS parts, total: $$SIZE"

# Generate release manifest
manifest:
    @mkdir -p splits
    @PARTS=$$(ls splits/*.part.* 2>/dev/null | wc -l)
    @SIZE=$$(du -sh splits 2>/dev/null | cut -f1)
    @echo '{"name":"{{output_name}}","version":"{{version}}","commit":"{{commit}}","date":"{{date}}","parts":'$$PARTS',"max_part_size":"{{max_part_size}}","total_size":"'$$SIZE'","features":["prowl","nmap","nuclei","httpx","subfinder","ffuf","gobuster","sqlmap","nikto","whatweb","wpscan","hydra","john","hashcat","metasploit","burpsuite","responder","bloodhound","binwalk","radare2","bettercap","mitmproxy","semgrep","dalfox","katana","gau"]}' > splits/manifest.json
    @echo "Manifest written to splits/manifest.json"

# Full Kali image build (all steps)
# Usage: just kali-image
#        IMAGE_TYPE=virtualbox just kali-image
kali-image: download-kali build-for-image create-work-image clean-image-caches install-prowl-image bundle-bounty-data install-tools-image compress-image split-image manifest
    @echo ""
    @echo "╔══════════════════════════════════════════════╗"
    @echo "║  Kali Image Build Complete!                  ║"
    @echo "╚══════════════════════════════════════════════╝"
    @echo ""
    @echo "  Type:    {{image_type}}"
    @echo "  QCOW2:   {{output_name}}.qcow2"
    @echo "  Splits:  splits/{{output_name}}.part.*"
    @echo "  Manifest: splits/manifest.json"
    @echo ""
    @echo "To reassemble:"
    @echo "  cat splits/{{output_name}}.part.* > {{output_name}}.qcow2"
    @echo ""
    @echo "To run:"
    @echo "  qemu-system-x86_64 -m 4G -smp 2 -enable-kvm \\"
    @echo "    -drive file={{output_name}}.qcow2,format=qcow2 \\"
    @echo "    -net user,hostfwd=tcp::2222-:22 -net nic"

# Quick build (skip tools, just prowl + clean)
kali-quick: download-kali build-for-image create-work-image clean-image-caches install-prowl-image compress-image split-image manifest
    @echo "Quick image built ({{image_type}}, no tool install)"

# Cleanup build artifacts
clean-image:
    rm -rf build/ splits/ {{output_name}}.qcow2
    @echo "Cleaned image build artifacts"

# Show image info
image-info:
    @if [ -f "{{output_name}}.qcow2" ]; then \
        echo "=== Image Info ==="; \
        qemu-img info "{{output_name}}.qcow2"; \
        echo ""; \
        echo "File size: $$(du -h {{output_name}}.qcow2 | cut -f1)"; \
        echo "Parts: $$(ls splits/*.part.* 2>/dev/null | wc -l)"; \
    else \
        echo "No image found. Run 'just kali-image' first."; \
    fi
