#!/bin/bash

set -e

echo "[*] Starting Security Pipeline setup..."

# =========================
# 1. System dependencies
# =========================
echo "[*] Installing system tools..."
sudo apt-get update
sudo apt-get install -y nmap sqlmap unzip wget curl tar

# =========================
# 2. Create bin directory
# =========================
BIN_DIR="$(pwd)/bin"
mkdir -p "$BIN_DIR"

echo "[*] Using bin directory: $BIN_DIR"

# =========================
# Helper: install binary safely
# =========================
install_binary() {
    local name=$1
    local zip_url=$2
    local binary_name=$3
    local extract_dir=$4

    echo "[*] Installing $name..."

    if [ -f "$BIN_DIR/$binary_name" ]; then
        echo "[*] $name already exists → skipping"
        return
    fi

    curl -L -o temp.zip "$zip_url"
    unzip -o temp.zip > /dev/null

    if [ -n "$extract_dir" ]; then
        BIN_PATH=$(find "$extract_dir" -type f -name "$binary_name" | head -n 1)
        rm -rf "$extract_dir"
    else
        BIN_PATH="./$binary_name"
    fi

    if [ ! -f "$BIN_PATH" ]; then
        echo "[!] Failed to locate $name binary"
        exit 1
    fi

    install -m 755 "$BIN_PATH" "$BIN_DIR/$binary_name"
    rm -f temp.zip
}

# =========================
# Helper: install .tar.gz safely (used by gau)
# =========================
install_binary_targz() {
    local name=$1
    local tar_url=$2
    local binary_name=$3
    local extract_dir=$4

    echo "[*] Installing $name..."

    if [ -f "$BIN_DIR/$binary_name" ]; then
        echo "[*] $name already exists → skipping"
        return
    fi

    curl -L -o temp.tar.gz "$tar_url"
    tar -xzf temp.tar.gz

    if [ -n "$extract_dir" ]; then
        BIN_PATH=$(find "$extract_dir" -type f -name "$binary_name" | head -n 1)
        rm -rf "$extract_dir"
    else
        BIN_PATH="./$binary_name"
    fi

    if [ ! -f "$BIN_PATH" ]; then
        echo "[!] Failed to locate $name binary"
        exit 1
    fi

    install -m 755 "$BIN_PATH" "$BIN_DIR/$binary_name"
    rm -f temp.tar.gz
}

# =========================
# 3. Nuclei
# =========================
install_binary \
"nuclei" \
"https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip" \
"nuclei" \
""

# =========================
# 4. HTTPX
# =========================
install_binary \
"httpx" \
"https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip" \
"httpx" \
""

# =========================
# 5. Gospider
# =========================
install_binary \
"gospider" \
"https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_linux_x86_64.zip" \
"gospider" \
"gospider_v1.1.6_linux_x86_64"

# =========================
# 6. Katana
# =========================
install_binary \
"katana" \
"https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana_1.5.0_linux_amd64.zip" \
"katana" \
""

# =========================
# 7. GAU
# =========================
install_binary_targz \
"gau" \
"https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz" \
"gau" \
""

# =========================
# 8. Permissions
# =========================
chmod +x "$BIN_DIR"/*

# =========================
# 7. PATH handling (safe)
# =========================
if ! grep -q "$BIN_DIR" ~/.bashrc; then
    echo "export PATH=\$PATH:$BIN_DIR" >> ~/.bashrc
fi

export PATH=$PATH:$BIN_DIR

echo "[*] Setup complete!"
echo "[*] Installed tools:"
echo "    nmap, sqlmap (system)"
echo "    nuclei, httpx, gospider, katana, gau (bin)"