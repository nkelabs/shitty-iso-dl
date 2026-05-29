#!/usr/bin/env python3
import os
import socket
import ssl
import sys
import json
import re
import urllib.request
import urllib.error

# Global socket timeout so a stalled mirror can't hang the bulk loop forever.
# Applies to both connect and per-read operations on the underlying socket.
socket.setdefaulttimeout(60)

# CA bundle resolution.
#
# When this script runs as `python3 shitty-iso-dl-cli.py`, the OS-provided
# CA store works fine. When it's frozen by PyInstaller (one-file binary or
# AppImage), the OS store isn't bundled and `ssl.create_default_context()`
# fails with CERTIFICATE_VERIFY_FAILED on every HTTPS request.
#
# Fix: use the `certifi` Mozilla CA bundle when it's installed. certifi is a
# proper Python package, so PyInstaller picks it up when invoked with
# `--collect-data certifi` (see .github/workflows/release.yml). For people
# running the .py directly without certifi installed, we fall back to the
# default context.
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX = ssl.create_default_context()


# Filenames here come from either scraped HTML (regex-matched) or the GitHub
# API (attacker-controllable). Even though current regexes are tight, we
# defensively clamp filenames to a plausible-ISO-name shape and refuse anything
# with path separators or query strings.
_SAFE_FILENAME = re.compile(r'^[A-Za-z0-9._+-]+\.iso$')

def safe_filename(url):
    # Strip any query string, then take only the basename component. This
    # neutralises both `../traversal.iso` and `evil.iso?download=x` shapes.
    name = url.split('?', 1)[0].split('#', 1)[0].rsplit('/', 1)[-1]
    if not _SAFE_FILENAME.match(name):
        raise ValueError(f"refusing suspicious filename: {name!r}")
    return name

# A redirect handler that lets normal cross-host 3xx through (legitimate for
# mirror systems and CDN handoffs) but refuses to downgrade HTTPS to HTTP.
# Combined with the lack of integrity checking on bare downloads, an attacker
# who controls any link in a redirect chain could otherwise silently substitute
# an ISO over a plaintext channel.
class _NoDowngradeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.full_url.startswith('https://') and newurl.startswith('http://'):
            raise urllib.error.HTTPError(
                req.full_url, code,
                f"refusing HTTPS->HTTP downgrade to {newurl}",
                headers, fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_SSL_CTX),
    _NoDowngradeRedirectHandler(),
)
_opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
urllib.request.install_opener(_opener)

# ---------------------------------------------------------
# set your download directory here, or leave blank 
# to be prompted when the script runs
# ---------------------------------------------------------
DEFAULT_DIR = "" 

# ---------------------------------------------------------
# defines how to find the latest version of each distro.
# - "direct": A static permalink that always points to the latest.
# - "github": Scrapes the latest release from a GitHub repo.
# - "regex": Scrapes an Apache/Nginx file index to find the highest version.
# ---------------------------------------------------------
DISTROS = {
    # the arch family
    "Arch": {
        "type": "direct",
        "url": "https://geo.mirror.pkgbuild.com/iso/latest/archlinux-x86_64.iso"
    },
    "Manjaro-KDE": {
        "type": "regex",
        "base_url": "https://mirror.easyname.at/manjaro/kde/",
        "dir_regex": r'href="([0-9\.]+)/"',
        "file_regex": r'href="(manjaro-kde-[0-9\.]+-linux[0-9]+\.iso)"'
    },
    "CachyOS": {
        "type": "regex",
        "base_url": "https://mirror.cachyos.org/ISO/desktop/",
        "dir_regex": r'href="([0-9]{6})/"',
        "file_regex": r'href="(cachyos-desktop-linux-[0-9]{6}\.iso)"'
    },
    "EndeavourOS": {
        "type": "github",
        "repo": "endeavouros-team/ISO"
    },
    "Artix": {
        "type": "regex",
        "base_url": "https://mirrors.dotsrc.org/artix-linux/isos/artix-base/",
        "file_regex": r'href="(artix-base-openrc-[0-9]+\.iso)"'
    },
    "Garuda-Dr460nized": {
        "type": "regex",
        "base_url": "https://iso.garudalinux.org/garuda/dr460nized/",
        "dir_regex": r'href="([0-9]+)/"',
        "file_regex": r'href="(garuda-dr460nized-linux-zen-[0-9]+\.iso)"'
    },
    "ArcoLinux": {
        "type": "regex",
        "base_url": "https://ftp.belnet.be/arcolinux/iso/",
        "dir_regex": r'href="(v[0-9\.]+)/"',
        "file_regex": r'href="(arcolinux-v[0-9\.]+-x86_64\.iso)"'
    },
    "BlackArch": {
        "type": "regex",
        "base_url": "https://blackarch.org/blackarch/iso/",
        "file_regex": r'href="(blackarch-linux-full-[0-9\.]+-x86_64-live\.iso)"'
    },

    # the debian family
    "Debian": {
        "type": "regex",
        "base_url": "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/",
        "file_regex": r'href="(debian-[0-9\.]+-amd64-netinst\.iso)"'
    },
    "Kali": {
        "type": "regex",
        "base_url": "https://cdimage.kali.org/kali-images/current/",
        "file_regex": r'href="(kali-linux-[0-9\.]+-installer-amd64\.iso)"'
    },
    "ParrotOS": {
        "type": "regex",
        "base_url": "https://deb.parrot.sh/parrot/iso/current/",
        "file_regex": r'href="(Parrot-security-[0-9\.]+_amd64\.iso)"'
    },
    "Tails": {
        "type": "regex",
        "base_url": "https://ftp.nluug.nl/os/Linux/distr/tails/tails/stable/",
        "dir_regex": r'href="tails-amd64-([0-9\.]+)/"',
        "file_regex": r'href="(tails-amd64-[0-9\.]+\.iso)"'
    },
    "Devuan": {
        "type": "regex",
        "base_url": "https://mirrors.dotsrc.org/devuan-cd/",
        "dir_regex": r'href="(devuan_(?!jessie)[a-z]+)/"',
        "file_regex": r'href="(devuan_[a-z]+_[0-9\.]+_amd64_desktop\.iso)"',
        "sub_path": "installer-iso/"
    },
    "Antix": {
        "type": "regex",
        "base_url": "https://mirrors.sonic.net/antix/",
        "dir_regex": r'href="(antiX-[0-9\.]+)/"',
        "file_regex": r'href="(antiX-[0-9\.]+_x64-full\.iso)"'
    },
    "MX-Linux": {
        "type": "regex",
        "base_url": "https://mirrors.sonic.net/mxlinux/iso/MX/Final/",
        "file_regex": r'href="(MX-[0-9\.]+_x64\.iso)"'
    },

    # the ubuntu family
    "Ubuntu": {
        "type": "regex",
        "base_url": "https://releases.ubuntu.com/",
        "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(ubuntu-[0-9\.]+-desktop-amd64\.iso)"'
    },
    "Kubuntu": {
        "type": "regex",
        "base_url": "https://cdimage.ubuntu.com/kubuntu/releases/",
        "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(kubuntu-[0-9\.]+-desktop-amd64\.iso)"',
        "sub_path": "release/"
    },
    "Xubuntu": {
        "type": "regex",
        "base_url": "https://cdimage.ubuntu.com/xubuntu/releases/",
        "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(xubuntu-[0-9\.]+-desktop-amd64\.iso)"',
        "sub_path": "release/"
    },
    "Lubuntu": {
        "type": "regex",
        "base_url": "https://cdimage.ubuntu.com/lubuntu/releases/",
        "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(lubuntu-[0-9\.]+-desktop-amd64\.iso)"',
        "sub_path": "release/"
    },
    "Ubuntu-MATE": {
        "type": "regex",
        "base_url": "https://cdimage.ubuntu.com/ubuntu-mate/releases/",
        "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(ubuntu-mate-[0-9\.]+-desktop-amd64\.iso)"',
        "sub_path": "release/"
    },
    "Mint": {
        "type": "regex",
        "base_url": "https://mirrors.kernel.org/linuxmint/stable/",
        "dir_regex": r'href="([0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(linuxmint-[0-9\.]+-cinnamon-64bit\.iso)"'
    },
    "Pop_OS": {
        "type": "regex",
        "base_url": "https://iso.pop-os.org/",
        "dir_regex": r'href="([0-9]+\.[0-9]+)/"',
        "file_regex": r'href="(pop-os_[0-9\.]+_amd64_nvidia_[0-9]+\.iso)"',
        "sub_path": "amd64/nvidia/"
    },
    "KDE-Neon": {
        "type": "regex",
        "base_url": "https://files.kde.org/neon/images/user/current/",
        "file_regex": r'href="(neon-user-[0-9]+\.iso)"'
    },
    "Linux-Lite": {
        "type": "regex",
        "base_url": "https://mirror.alpix.eu/linuxlite/isos/",
        "dir_regex": r'href="([0-9\.]+)/"',
        "file_regex": r'href="(linux-lite-[0-9\.]+-64bit\.iso)"'
    },
    "Trisquel": {
        "type": "regex",
        "base_url": "https://cdimage.trisquel.info/trisquel-images/",
        "file_regex": r'href="(trisquel_[0-9\.]+_amd64\.iso)"'
    },

    # the red hat / fedora family
    "Fedora": {
        "type": "regex",
        "base_url": "https://mirrors.kernel.org/fedora/releases/",
        "dir_regex": r'href="([0-9]+)/"',
        "file_regex": r'href="(Fedora-Workstation-Live-x86_64-[0-9\.-]+\.iso)"',
        "sub_path": "Workstation/x86_64/iso/"
    },
    "Rocky": {
        "type": "regex",
        "base_url": "https://download.rockylinux.org/pub/rocky/",
        "dir_regex": r'href="([0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(Rocky-[0-9\.]+-x86_64-dvd[0-9]*\.iso)"',
        "sub_path": "isos/x86_64/"
    },
    "AlmaLinux": {
        "type": "regex",
        "base_url": "https://repo.almalinux.org/almalinux/",
        "dir_regex": r'href="([0-9]+(\.[0-9]+)?)/"',
        "file_regex": r'href="(AlmaLinux-[0-9\.]+-x86_64-dvd\.iso)"',
        "sub_path": "isos/x86_64/"
    },
    "CentOS-Stream": {
        "type": "regex",
        "base_url": "https://mirror.stream.centos.org/",
        "dir_regex": r'href="([0-9]+-stream)/"',
        "file_regex": r'href="(CentOS-Stream-[0-9]+-latest-x86_64-dvd[0-9]*\.iso)"',
        "sub_path": "BaseOS/x86_64/iso/"
    },
    "Qubes-OS": {
        "type": "regex",
        "base_url": "https://mirrors.edge.kernel.org/qubes/iso/",
        "file_regex": r'href="(Qubes-R[0-9\.]+-x86_64\.iso)"'
    },

    # the suse / slackware / mandriva families
    "openSUSE-Tumbleweed": {
        "type": "direct",
        "url": "https://download.opensuse.org/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso"
    },
    "Slackware": {
        "type": "regex",
        "base_url": "https://mirrors.kernel.org/slackware/",
        "dir_regex": r'href="(slackware64-[0-9\.]+)/"',
        "file_regex": r'href="(slackware64-[0-9\.]+-install-dvd\.iso)"',
        "sub_path": "iso/"
    },
    "Mageia": {
        "type": "regex",
        "base_url": "https://mirrors.kernel.org/mageia/iso/",
        "dir_regex": r'href="([0-9]+)/"',
        "file_regex": r'href="(Mageia-[0-9]+-Live-Plasma-x86_64\.iso)"',
        "sub_path": "Mageia-Live-Plasma-x86_64/"
    },
    "PCLinuxOS": {
        "type": "regex",
        "base_url": "https://ftp.nluug.nl/pub/os/Linux/distr/pclinuxos/pclinuxos/iso/",
        "file_regex": r'href="(pclinuxos64-kde-[0-9\.]+\.iso)"'
    },

    # independent, niche and speciality
    "Void": {
        "type": "regex",
        "base_url": "https://repo-default.voidlinux.org/live/current/",
        "file_regex": r'href="(void-live-x86_64-[0-9]{8}-base\.iso)"'
    },
    "NixOS": {
        "type": "regex",
        "base_url": "https://channels.nixos.org/nixos-unstable/",
        "file_regex": r'href="(nixos-plasma5-[0-9\.]+-x86_64-linux\.iso)"'
    },
    "Gentoo": {
        "type": "regex",
        "base_url": "https://distfiles.gentoo.org/releases/amd64/autobuilds/",
        "dir_regex": r'href="(current-install-amd64-minimal)/"',
        "file_regex": r'href="(install-amd64-minimal-[0-9TZ]+\.iso)"'
    },
    "Alpine": {
        "type": "regex",
        "base_url": "https://dl-cdn.alpinelinux.org/alpine/",
        "dir_regex": r'href="(v[0-9]+\.[0-9]+)/"',
        "file_regex": r'href="(alpine-standard-[0-9\.]+-x86_64\.iso)"',
        "sub_path": "releases/x86_64/"
    },
    "Deepin": {
        "type": "regex",
        "base_url": "https://cdimage.deepin.com/releases/",
        "dir_regex": r'href="([0-9\.]+)/"',
        "file_regex": r'href="(deepin-desktop-community-[0-9\.]+-amd64\.iso)"'
    },
    "ClearLinux": {
        "type": "regex",
        "base_url": "https://cdn.download.clearlinux.org/current/",
        "file_regex": r'href="(clear-[0-9]+-live-desktop\.iso)"'
    },
    "Puppy-Linux": {
        "type": "regex",
        "base_url": "https://distro.ibiblio.org/puppylinux/puppy-fossa/",
        "file_regex": r'href="(fossapup64-[0-9\.]+\.iso)"'
    },
    "TinyCore": {
        "type": "regex",
        "base_url": "https://tinycorelinux.net/14.x/x86_64/release/",
        "file_regex": r'href="(CorePure64-[0-9\.]+\.iso)"'
    },
    "GoboLinux": {
        "type": "github",
        "repo": "gobolinux/LiveCD"
    },
    "KaOS": {
        "type": "regex",
        "base_url": "https://mirrors.kernel.org/kaos/iso/",
        "dir_regex": r'href="([0-9\.]+)/"',
        "file_regex": r'href="(KaOS-[0-9\.]+-x86_64\.iso)"'
    },
    "Calculate-Linux": {
        "type": "regex",
        "base_url": "https://mirror.yandex.ru/calculate/release/",
        "dir_regex": r'href="([0-9\.]+)/"',
        "file_regex": r'href="(cld-[0-9\.]+-x86_64\.iso)"'
    },
    "Grml": {
        "type": "regex",
        "base_url": "https://download.grml.org/",
        "file_regex": r'href="(grml64-full_[0-9\.-]+\.iso)"'
    },
    "SystemRescue": {
        "type": "regex",
        "base_url": "https://mirror.rackspace.com/systemrescuecd/releases/",
        "dir_regex": r'href="([0-9\.]+)/"',
        "file_regex": r'href="(systemrescue-[0-9\.]+-amd64\.iso)"'
    },
    "Proxmox-VE": {
        "type": "regex",
        "base_url": "https://enterprise.proxmox.com/iso/",
        "file_regex": r'href="(proxmox-ve_[0-9\.-]+\.iso)"'
    },
    "TrueNAS-SCALE": {
        "type": "regex",
        "base_url": "https://download.truenas.com/TrueNAS-SCALE-Dragonfish/",
        "dir_regex": r'href="([0-9\.]+)/"',
        "file_regex": r'href="(TrueNAS-SCALE-[0-9\.-]+\.iso)"'
    }
}

def get_html(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode('utf-8')

# Natural-key sort: splits a string into runs of digits and non-digits so
# that numeric runs compare as integers. Without this, plain sorted() picks
# '9' as "latest" over '10', breaking Mageia, Tails, Rocky, Devuan,
# CentOS-Stream, and any future distro that crosses a digit-count boundary.
def _natural_key(s):
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r'(\d+)', s)]

# ---------------------------------------------------------
# Optional SHA256 verification.
#
# Caveat: the SHA file is usually hosted next to the ISO on the same mirror,
# so this is NOT protection against a compromised mirror -- it only catches
# transport corruption and the most casual tampering. Real protection needs
# GPG-signed checksum files, which is per-distro work and not yet implemented.
# ---------------------------------------------------------
_SHA_CANDIDATES = ("SHA256SUMS", "sha256sums", "sha256sums.txt", "SHA256SUMS.txt", "sha256sum.txt", "SHA256SUM.txt", "sha256", "SHA256")

def _parse_sha256_for(text, iso_filename):
    # Accept the two common layouts:
    #   "<hash>  <filename>"   (coreutils sha256sum)
    #   "SHA256 (<filename>) = <hash>"   (BSD style)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('SHA256') and '=' in line and iso_filename in line:
            hexpart = line.split('=', 1)[1].strip().split()[0]
            if re.fullmatch(r'[0-9a-fA-F]{64}', hexpart):
                return hexpart.lower()
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r'[0-9a-fA-F]{64}', parts[0]):
            # Filename may be prefixed with '*' (binary mode) or './'.
            tail = parts[-1].lstrip('*').lstrip('./')
            if tail == iso_filename:
                return parts[0].lower()
    return None

def fetch_expected_sha256(iso_url, iso_filename):
    base = iso_url.rsplit('/', 1)[0] + '/'
    # Try a per-file sidecar first (e.g. foo.iso.sha256), then directory-wide files.
    sidecars = (f"{iso_filename}.sha256", f"{iso_filename}.sha256sum")
    for candidate in sidecars + _SHA_CANDIDATES:
        try:
            text = get_html(base + candidate)
        except Exception:
            continue
        # Sidecar files often contain just the hash, possibly followed by the name.
        if candidate in sidecars:
            first = text.strip().split()
            if first and re.fullmatch(r'[0-9a-fA-F]{64}', first[0]):
                return first[0].lower()
        got = _parse_sha256_for(text, iso_filename)
        if got:
            return got
    return None

def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def find_latest_via_regex(config):
    base_url = config['base_url']

    # Step 1: If the ISOs are hidden inside a versioned folder
    if 'dir_regex' in config:
        try:
            html = get_html(base_url)
        except Exception as e:
            print(f"  [!] Error reading base directory {base_url}: {e}")
            return None

        dirs = re.findall(config['dir_regex'], html)
        if not dirs:
            return None

        # Extract string if regex returns tuples, sort to find highest version
        dirs = [d[0] if isinstance(d, tuple) else d for d in dirs]
        sorted_dirs = sorted(dirs, key=_natural_key)

        # Try directories from newest to oldest (handles empty/half-synced staging folders)
        for latest_dir in reversed(sorted_dirs):
            target_url = base_url + latest_dir + "/"
            if 'sub_path' in config:
                target_url += config['sub_path']

            try:
                html = get_html(target_url)
                files = re.findall(config['file_regex'], html)
                if files:
                    files = [f[0] if isinstance(f, tuple) else f for f in files]
                    latest_file = sorted(files, key=_natural_key)[-1]
                    iso_url = target_url + latest_file

                    # Validate that the SHA file is ALSO present in this folder.
                    # If it's missing, the mirror is incomplete. Fall back to the older folder.
                    if fetch_expected_sha256(iso_url, latest_file):
                        return iso_url
                    else:
                        continue
            except Exception:
                continue

        print(f"  [!] Could not find any complete releases (ISO + SHA) in {base_url}")
        return None

    else:
        # Step 2 logic for direct directories (no sub-folders to fall back on)
        target_url = base_url
        try:
            html = get_html(target_url)
            files = re.findall(config['file_regex'], html)
            if not files:
                return None
            files = [f[0] if isinstance(f, tuple) else f for f in files]
            latest_file = sorted(files, key=_natural_key)[-1]
            return target_url + latest_file
        except Exception as e:
            print(f"  [!] Error reading {target_url}: {e}")
            return None
def find_latest_github(repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))
            for asset in data.get('assets', []):
                if asset['name'].endswith('.iso'):
                    return asset['browser_download_url']
    except Exception as e:
        print(f"  [!] GitHub API error: {e}")
    return None

def download_file(url, dest_folder, verify_sha256=False):
    try:
        file_name = safe_filename(url)
    except ValueError as e:
        print(f"  [!] {e}")
        return False
    dest_path = os.path.join(dest_folder, file_name)
    tmp_path = dest_path + '.part'

    if os.path.exists(dest_path):
        print(f"  [*] {file_name} already exists. Skipping.")
        return True

    expected_sha = None
    if verify_sha256:
        print(f"  [*] Looking up SHA256 for {file_name}...")
        try:
            expected_sha = fetch_expected_sha256(url, file_name)
        except Exception as e:
            print(f"  [!] Could not fetch SHA256 file: {e}")
        if expected_sha is None:
            print(f"  [!] No SHA256 found for {file_name}; refusing download (use without --verify to skip).")
            return False
        print(f"  [*] Expected SHA256: {expected_sha}")

    print(f"  [*] Downloading {file_name}...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        # Download to .part first so an interrupted/aborted download is not
        # mistaken for a finished one on the next run.
        with urllib.request.urlopen(req, timeout=60) as response, open(tmp_path, 'wb') as out_file:
            file_size = int(response.info().get('Content-Length', -1))
            downloaded = 0
            block_size = 1024 * 8

            while True:
                buffer = response.read(block_size)
                if not buffer:
                    break
                downloaded += len(buffer)
                out_file.write(buffer)

                if file_size > 0:
                    percent = downloaded * 100 / file_size
                    mb_downloaded = downloaded / (1024 * 1024)
                    mb_total = file_size / (1024 * 1024)
                    sys.stdout.write(f"\r      Progress: {percent:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)")
                    sys.stdout.flush()

        # Sanity check: if the server told us a size, make sure we got it.
        if file_size > 0 and downloaded != file_size:
            raise IOError(f"size mismatch: got {downloaded} bytes, expected {file_size}")

        # Verify checksum BEFORE the rename, so a mismatched file never lands
        # under its final name where the next run would treat it as complete.
        if expected_sha is not None:
            print("\n  [*] Verifying SHA256...")
            actual = sha256_file(tmp_path)
            if actual.lower() != expected_sha.lower():
                raise IOError(f"SHA256 mismatch: got {actual}, expected {expected_sha}")
            print("  [+] SHA256 OK.")

        os.replace(tmp_path, dest_path)
        print("\n  [+] Download complete!")
        return True
    except BaseException as e:
        # BaseException so we also clean up on Ctrl-C / SystemExit.
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        if isinstance(e, KeyboardInterrupt):
            print("\n  [!] Interrupted by user.")
            raise
        print(f"\n  [!] Failed to download: {e}")
        return False

def main():
    print("=== Linux ISO Auto-Puller ===")

    # Support `--verify` as a non-interactive flag in addition to the prompt.
    verify_sha256 = '--verify' in sys.argv[1:]

    # Get Destination
    dest_dir = DEFAULT_DIR
    if not dest_dir:
        dest_dir = input("Enter destination directory (e.g., /mnt/isos): ").strip()
    
    if not os.path.exists(dest_dir):
        try:
            os.makedirs(dest_dir)
            print(f"[+] Created directory: {dest_dir}")
        except Exception as e:
            print(f"[!] Could not create directory: {e}")
            sys.exit(1)

    if not verify_sha256:
        ans = input("Verify SHA256 after download? (y/N): ").strip().lower()
        verify_sha256 = ans in ('y', 'yes')

    # Show Menu
    distro_names = list(DISTROS.keys())
    print("\nAvailable Distributions:")
    for i, name in enumerate(distro_names, 1):
        print(f"  {i}. {name}")
    print("  A. All")
    
    choice = input("\nWhich distros to update? (e.g., 1,3,4 or A): ").strip().upper()
    
    selected_distros = []
    if choice == 'A':
        selected_distros = distro_names
    else:
        try:
            indices = [int(x.strip()) - 1 for x in choice.split(',')]
            selected_distros = [distro_names[i] for i in indices if 0 <= i < len(distro_names)]
        except ValueError:
            print("[!] Invalid input. Exiting.")
            sys.exit(1)

    # Process Selections
    failures = []
    for distro in selected_distros:
        print(f"\n>>> Processing {distro}...")
        config = DISTROS[distro]
        download_url = None

        if config['type'] == 'direct':
            download_url = config['url']
        elif config['type'] == 'github':
            download_url = find_latest_github(config['repo'])
        elif config['type'] == 'regex':
            download_url = find_latest_via_regex(config)

        if download_url:
            print(f"  [*] Found latest: {download_url}")
            ok = download_file(download_url, dest_dir, verify_sha256=verify_sha256)
            if not ok:
                failures.append((distro, "download failed"))
        else:
            print("  [!] Could not resolve a download URL.")
            failures.append((distro, "URL not resolved"))

    # Final summary so per-distro failures don't get lost in a long bulk run.
    print("\n=== Done ===")
    succeeded = len(selected_distros) - len(failures)
    print(f"  Succeeded: {succeeded}/{len(selected_distros)}")
    if failures:
        print("  Failed:")
        for name, reason in failures:
            print(f"    - {name}: {reason}")

if __name__ == "__main__":
    main()
