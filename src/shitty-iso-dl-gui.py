#!/usr/bin/env python3
import json
import re
import socket
import ssl
import time
import urllib.request
import urllib.error
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Global socket timeout so a stalled mirror can't hang the worker forever.
# Applies to connect and to per-read operations on the underlying socket.
socket.setdefaulttimeout(60)

# CA bundle resolution.
#
# When this script runs as `python3 shitty-iso-dl-gui.py`, the OS-provided
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
    name = url.split('?', 1)[0].split('#', 1)[0].rsplit('/', 1)[-1]
    if not _SAFE_FILENAME.match(name):
        raise ValueError(f"refusing suspicious filename: {name!r}")
    return name

# A redirect handler that lets normal cross-host 3xx through (legitimate for
# mirror systems and CDN handoffs) but refuses to downgrade HTTPS to HTTP.
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

DISTROS = {
    "Arch": {"type": "direct", "url": "https://geo.mirror.pkgbuild.com/iso/latest/archlinux-x86_64.iso"},
    "Manjaro-KDE": {"type": "regex", "base_url": "https://mirror.easyname.at/manjaro/kde/", "dir_regex": r'href="([0-9\.]+)/"', "file_regex": r'href="(manjaro-kde-[0-9\.]+-linux[0-9]+\.iso)"'},
    "CachyOS": {"type": "regex", "base_url": "https://mirror.cachyos.org/ISO/desktop/", "dir_regex": r'href="([0-9]{6})/"', "file_regex": r'href="(cachyos-desktop-linux-[0-9]{6}\.iso)"'},
    "EndeavourOS": {"type": "github", "repo": "endeavouros-team/ISO"},
    "Artix": {"type": "regex", "base_url": "https://mirrors.dotsrc.org/artix-linux/isos/artix-base/", "file_regex": r'href="(artix-base-openrc-[0-9]+\.iso)"'},
    "Garuda-Dr460nized": {"type": "regex", "base_url": "https://iso.garudalinux.org/garuda/dr460nized/", "dir_regex": r'href="([0-9]+)/"', "file_regex": r'href="(garuda-dr460nized-linux-zen-[0-9]+\.iso)"'},
    "ArcoLinux": {"type": "regex", "base_url": "https://ftp.belnet.be/arcolinux/iso/", "dir_regex": r'href="(v[0-9\.]+)/"', "file_regex": r'href="(arcolinux-v[0-9\.]+-x86_64\.iso)"'},
    "BlackArch": {"type": "regex", "base_url": "https://blackarch.org/blackarch/iso/", "file_regex": r'href="(blackarch-linux-full-[0-9\.]+-x86_64-live\.iso)"'},
    "Debian": {"type": "regex", "base_url": "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/", "file_regex": r'href="(debian-[0-9\.]+-amd64-netinst\.iso)"'},
    "Kali": {"type": "regex", "base_url": "https://cdimage.kali.org/kali-images/current/", "file_regex": r'href="(kali-linux-[0-9\.]+-installer-amd64\.iso)"'},
    "ParrotOS": {"type": "regex", "base_url": "https://deb.parrot.sh/parrot/iso/current/", "file_regex": r'href="(Parrot-security-[0-9\.]+_amd64\.iso)"'},
    "Tails": {"type": "regex", "base_url": "https://ftp.nluug.nl/os/Linux/distr/tails/tails/stable/", "dir_regex": r'href="tails-amd64-([0-9\.]+)/"', "file_regex": r'href="(tails-amd64-[0-9\.]+\.iso)"'},
    "Devuan": {"type": "regex", "base_url": "https://mirrors.kernel.org/devuan/", "dir_regex": r'href="(devuan_[0-9]+)/"', "file_regex": r'href="(devuan_[0-9\.]+_amd64_desktop\.iso)"', "sub_path": "installer-iso/"},
    "Antix": {"type": "regex", "base_url": "https://mirrors.sonic.net/antix/", "dir_regex": r'href="(antiX-[0-9\.]+)/"', "file_regex": r'href="(antiX-[0-9\.]+_x64-full\.iso)"'},
    "MX-Linux": {"type": "regex", "base_url": "https://mirrors.sonic.net/mxlinux/iso/MX/Final/", "file_regex": r'href="(MX-[0-9\.]+_x64\.iso)"'},
    "Ubuntu": {"type": "regex", "base_url": "https://releases.ubuntu.com/", "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(ubuntu-[0-9\.]+-desktop-amd64\.iso)"'},
    "Kubuntu": {"type": "regex", "base_url": "https://cdimage.ubuntu.com/kubuntu/releases/", "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(kubuntu-[0-9\.]+-desktop-amd64\.iso)"', "sub_path": "release/"},
    "Xubuntu": {"type": "regex", "base_url": "https://cdimage.ubuntu.com/xubuntu/releases/", "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(xubuntu-[0-9\.]+-desktop-amd64\.iso)"', "sub_path": "release/"},
    "Lubuntu": {"type": "regex", "base_url": "https://cdimage.ubuntu.com/lubuntu/releases/", "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(lubuntu-[0-9\.]+-desktop-amd64\.iso)"', "sub_path": "release/"},
    "Ubuntu-MATE": {"type": "regex", "base_url": "https://cdimage.ubuntu.com/ubuntu-mate/releases/", "dir_regex": r'href="([0-9]+\.[0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(ubuntu-mate-[0-9\.]+-desktop-amd64\.iso)"', "sub_path": "release/"},
    "Mint": {"type": "regex", "base_url": "https://mirrors.kernel.org/linuxmint/stable/", "dir_regex": r'href="([0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(linuxmint-[0-9\.]+-cinnamon-64bit\.iso)"'},
    "Pop_OS": {"type": "regex", "base_url": "https://iso.pop-os.org/", "dir_regex": r'href="([0-9]+\.[0-9]+)/"', "file_regex": r'href="(pop-os_[0-9\.]+_amd64_nvidia_[0-9]+\.iso)"', "sub_path": "amd64/nvidia/"},
    "KDE-Neon": {"type": "regex", "base_url": "https://files.kde.org/neon/images/user/current/", "file_regex": r'href="(neon-user-[0-9]+\.iso)"'},
    "Linux-Lite": {"type": "regex", "base_url": "https://mirror.alpix.eu/linuxlite/isos/", "dir_regex": r'href="([0-9\.]+)/"', "file_regex": r'href="(linux-lite-[0-9\.]+-64bit\.iso)"'},
    "Trisquel": {"type": "regex", "base_url": "https://cdimage.trisquel.info/trisquel-images/", "file_regex": r'href="(trisquel_[0-9\.]+_amd64\.iso)"'},
    "Fedora": {"type": "regex", "base_url": "https://mirrors.kernel.org/fedora/releases/", "dir_regex": r'href="([0-9]+)/"', "file_regex": r'href="(Fedora-Workstation-Live-x86_64-[0-9\.-]+\.iso)"', "sub_path": "Workstation/x86_64/iso/"},
    "Rocky": {"type": "regex", "base_url": "https://download.rockylinux.org/pub/rocky/", "dir_regex": r'href="([0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(Rocky-[0-9\.]+-x86_64-dvd[0-9]*\.iso)"', "sub_path": "isos/x86_64/"},
    "AlmaLinux": {"type": "regex", "base_url": "https://repo.almalinux.org/almalinux/", "dir_regex": r'href="([0-9]+(\.[0-9]+)?)/"', "file_regex": r'href="(AlmaLinux-[0-9\.]+-x86_64-dvd\.iso)"', "sub_path": "isos/x86_64/"},
    "CentOS-Stream": {"type": "regex", "base_url": "https://mirror.stream.centos.org/", "dir_regex": r'href="([0-9]+-stream)/"', "file_regex": r'href="(CentOS-Stream-[0-9]+-latest-x86_64-dvd[0-9]*\.iso)"', "sub_path": "BaseOS/x86_64/iso/"},
    "Qubes-OS": {"type": "regex", "base_url": "https://mirrors.edge.kernel.org/qubes/iso/", "file_regex": r'href="(Qubes-R[0-9\.]+-x86_64\.iso)"'},
    "openSUSE-Tumbleweed": {"type": "direct", "url": "https://download.opensuse.org/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso"},
    "Slackware": {"type": "regex", "base_url": "https://mirrors.kernel.org/slackware/", "dir_regex": r'href="(slackware64-[0-9\.]+)/"', "file_regex": r'href="(slackware64-[0-9\.]+-install-dvd\.iso)"', "sub_path": "iso/"},
    "Mageia": {"type": "regex", "base_url": "https://mirrors.kernel.org/mageia/iso/", "dir_regex": r'href="([0-9]+)/"', "file_regex": r'href="(Mageia-[0-9]+-Live-Plasma-x86_64\.iso)"', "sub_path": "Mageia-Live-Plasma-x86_64/"},
    "PCLinuxOS": {"type": "regex", "base_url": "https://ftp.nluug.nl/pub/os/Linux/distr/pclinuxos/pclinuxos/iso/", "file_regex": r'href="(pclinuxos64-kde-[0-9\.]+\.iso)"'},
    "Void": {"type": "regex", "base_url": "https://repo-default.voidlinux.org/live/current/", "file_regex": r'href="(void-live-x86_64-[0-9]{8}-base\.iso)"'},
    "NixOS": {"type": "regex", "base_url": "https://channels.nixos.org/nixos-unstable/", "file_regex": r'href="(nixos-plasma5-[0-9\.]+-x86_64-linux\.iso)"'},
    "Gentoo": {"type": "regex", "base_url": "https://distfiles.gentoo.org/releases/amd64/autobuilds/", "dir_regex": r'href="(current-install-amd64-minimal)/"', "file_regex": r'href="(install-amd64-minimal-[0-9TZ]+\.iso)"'},
    "Alpine": {"type": "regex", "base_url": "https://dl-cdn.alpinelinux.org/alpine/", "dir_regex": r'href="(v[0-9]+\.[0-9]+)/"', "file_regex": r'href="(alpine-standard-[0-9\.]+-x86_64\.iso)"', "sub_path": "releases/x86_64/"},
    "Deepin": {"type": "regex", "base_url": "https://cdimage.deepin.com/releases/", "dir_regex": r'href="([0-9\.]+)/"', "file_regex": r'href="(deepin-desktop-community-[0-9\.]+-amd64\.iso)"'},
    "ClearLinux": {"type": "regex", "base_url": "https://cdn.download.clearlinux.org/current/", "file_regex": r'href="(clear-[0-9]+-live-desktop\.iso)"'},
    "Puppy-Linux": {"type": "regex", "base_url": "https://distro.ibiblio.org/puppylinux/puppy-fossa/", "file_regex": r'href="(fossapup64-[0-9\.]+\.iso)"'},
    "TinyCore": {"type": "regex", "base_url": "https://tinycorelinux.net/14.x/x86_64/release/", "file_regex": r'href="(CorePure64-[0-9\.]+\.iso)"'},
    "GoboLinux": {"type": "github", "repo": "gobolinux/LiveCD"},
    "KaOS": {"type": "regex", "base_url": "https://mirrors.kernel.org/kaos/iso/", "dir_regex": r'href="([0-9\.]+)/"', "file_regex": r'href="(KaOS-[0-9\.]+-x86_64\.iso)"'},
    "Calculate-Linux": {"type": "regex", "base_url": "https://mirror.yandex.ru/calculate/release/", "dir_regex": r'href="([0-9\.]+)/"', "file_regex": r'href="(cld-[0-9\.]+-x86_64\.iso)"'},
    "Grml": {"type": "regex", "base_url": "https://download.grml.org/", "file_regex": r'href="(grml64-full_[0-9\.-]+\.iso)"'},
    "SystemRescue": {"type": "regex", "base_url": "https://mirror.rackspace.com/systemrescuecd/releases/", "dir_regex": r'href="([0-9\.]+)/"', "file_regex": r'href="(systemrescue-[0-9\.]+-amd64\.iso)"'},
    "Proxmox-VE": {"type": "regex", "base_url": "https://enterprise.proxmox.com/iso/", "file_regex": r'href="(proxmox-ve_[0-9\.-]+\.iso)"'},
    "TrueNAS-SCALE": {"type": "regex", "base_url": "https://download.truenas.com/TrueNAS-SCALE-Dragonfish/", "dir_regex": r'href="([0-9\.]+)/"', "file_regex": r'href="(TrueNAS-SCALE-[0-9\.-]+\.iso)"'}
}


class ScraperEngine:
    # Natural-key sort: splits a string into runs of digits and non-digits so
    # that numeric runs compare as integers. Without this, plain sorted() picks
    # '9' as "latest" over '10', breaking Mageia, Tails, Rocky, Devuan,
    # CentOS-Stream, and any future distro that crosses a digit-count boundary.
    @staticmethod
    def _natural_key(s):
        return [int(p) if p.isdigit() else p.lower() for p in re.split(r'(\d+)', s)]

    # ---- SHA256 verification (optional) ------------------------------------
    # Caveat: the SHA file is usually hosted next to the ISO on the same mirror,
    # so this catches transport corruption but not a compromised mirror. Real
    # protection needs GPG-signed checksum files (per-distro work, not yet done).
    _SHA_CANDIDATES = ("SHA256SUMS", "sha256sums.txt", "sha256sum.txt", "SHA256")

    @staticmethod
    def _parse_sha256_for(text, iso_filename):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # BSD style: "SHA256 (file) = hash"
            if line.startswith('SHA256') and '=' in line and iso_filename in line:
                hexpart = line.split('=', 1)[1].strip().split()[0]
                if re.fullmatch(r'[0-9a-fA-F]{64}', hexpart):
                    return hexpart.lower()
            # coreutils style: "hash  file" (with optional '*' or './' prefix on the name)
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r'[0-9a-fA-F]{64}', parts[0]):
                tail = parts[-1].lstrip('*').lstrip('./')
                if tail == iso_filename:
                    return parts[0].lower()
        return None

    @classmethod
    def fetch_expected_sha256(cls, iso_url, iso_filename, status_cb):
        base = iso_url.rsplit('/', 1)[0] + '/'
        sidecars = (f"{iso_filename}.sha256", f"{iso_filename}.sha256sum")
        for candidate in sidecars + cls._SHA_CANDIDATES:
            text = cls.get_html(base + candidate, lambda _msg: None)
            if not text:
                continue
            if candidate in sidecars:
                first = text.strip().split()
                if first and re.fullmatch(r'[0-9a-fA-F]{64}', first[0]):
                    return first[0].lower()
            got = cls._parse_sha256_for(text, iso_filename)
            if got:
                return got
        return None

    @staticmethod
    def _sha256_file(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()
    # ------------------------------------------------------------------------

    @staticmethod
    def get_html(url, status_cb):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.read().decode('utf-8')
        except Exception as e:
            status_cb(f"Error reading {url}: {e}")
            return None

    @classmethod
    def find_latest_via_regex(cls, config, status_cb):
        base_url = config['base_url']
        
        if 'dir_regex' in config:
            html = cls.get_html(base_url, status_cb)
            if not html: return None
            
            dirs = re.findall(config['dir_regex'], html)
            if not dirs: return None
            
            dirs = [d[0] if isinstance(d, tuple) else d for d in dirs]
            latest_dir = sorted(dirs, key=cls._natural_key)[-1]
            target_url = f"{base_url}{latest_dir}/"
            
            if 'sub_path' in config:
                target_url += config['sub_path']
        else:
            target_url = base_url

        html = cls.get_html(target_url, status_cb)
        if not html: return None
        
        files = re.findall(config['file_regex'], html)
        if not files: return None
        
        files = [f[0] if isinstance(f, tuple) else f for f in files]
        latest_file = sorted(files, key=cls._natural_key)[-1]
        return target_url + latest_file

    @classmethod
    def find_latest_github(cls, repo, status_cb):
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                for asset in data.get('assets', []):
                    if asset['name'].endswith('.iso'):
                        return asset['browser_download_url']
        except Exception as e:
            status_cb(f"GitHub API error: {e}")
        return None

    @staticmethod
    def download_file(url, dest_folder, status_cb, progress_cb, verify_sha256=False):
        try:
            file_name = safe_filename(url)
        except ValueError as e:
            status_cb(str(e))
            return False
        dest_path = Path(dest_folder) / file_name
        tmp_path = dest_path.with_suffix(dest_path.suffix + '.part')

        if dest_path.exists():
            status_cb(f"{file_name} already exists. Skipping.")
            return True

        expected_sha = None
        if verify_sha256:
            status_cb(f"Looking up SHA256 for {file_name}...")
            try:
                expected_sha = ScraperEngine.fetch_expected_sha256(url, file_name, status_cb)
            except Exception as e:
                status_cb(f"Could not fetch SHA256 file: {e}")
            if expected_sha is None:
                status_cb(f"No SHA256 found for {file_name}; refusing (uncheck Verify to skip).")
                return False

        status_cb(f"Downloading {file_name}...")
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
                        mb_down = downloaded / (1024 * 1024)
                        mb_tot = file_size / (1024 * 1024)
                        progress_cb(percent, mb_down, mb_tot)

            # Sanity check: if the server told us a size, make sure we got it.
            if file_size > 0 and downloaded != file_size:
                raise IOError(f"size mismatch: got {downloaded} bytes, expected {file_size}")

            # Verify checksum BEFORE the rename, so a mismatched file never lands
            # under its final name where the next run would treat it as complete.
            if expected_sha is not None:
                status_cb(f"Verifying SHA256 for {file_name}...")
                actual = ScraperEngine._sha256_file(tmp_path)
                if actual.lower() != expected_sha.lower():
                    raise IOError(f"SHA256 mismatch: got {actual}, expected {expected_sha}")

            tmp_path.replace(dest_path)
            status_cb(f"Successfully downloaded {file_name}")
            return True
        except BaseException as e:
            # BaseException so we also clean up on Ctrl-C / SystemExit.
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            if isinstance(e, KeyboardInterrupt):
                raise
            status_cb(f"Failed to download: {e}")
            return False


class DistrohopperApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Shitty ISO Downloader")
        self.geometry("500x650")
        
        self.bg_color = "#1a1e29"   
        self.sec_bg_color = "#242a3a"    
        self.accent_color = "#c785a8"    
        self.text_color = "#dce0e8"      
        self.configure(bg=self.bg_color)

        self._setup_styles()
        self._build_ui()
        
        self.download_thread = None
        # Throttle state for _update_progress: avoid flooding the Tk event
        # queue with hundreds of thousands of after() calls per multi-GB ISO.
        self._last_progress_emit = 0.0

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        
        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabel", background=self.bg_color, foreground=self.text_color, font=("Helvetica", 10))
        
        style.configure("Title.TLabel", font=("Helvetica", 24, "bold"), foreground=self.accent_color)
        
        style.configure("TButton", background=self.sec_bg_color, foreground=self.text_color, 
                        borderwidth=0, focuscolor=self.sec_bg_color, padding=8, font=("Helvetica", 10, "bold"))
        style.map("TButton", background=[("active", self.accent_color)])
        
        style.configure("Horizontal.TProgressbar", background=self.accent_color, troughcolor=self.sec_bg_color, 
                        bordercolor=self.bg_color, lightcolor=self.accent_color, darkcolor=self.accent_color)

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Shitty ISO Downloader", style="Title.TLabel").pack(pady=(0, 20))

        # Destination Directory
        dir_frame = ttk.Frame(main_frame)
        dir_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.dir_var = tk.StringVar(value=str(Path.home() / "Downloads"))
        ttk.Label(dir_frame, text="Destination:").pack(side=tk.LEFT, padx=(0, 10))
        
        dir_entry = tk.Entry(dir_frame, textvariable=self.dir_var, bg=self.sec_bg_color, fg=self.text_color, 
                             insertbackground=self.text_color, borderwidth=0, highlightthickness=0)
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 10))
        
        ttk.Button(dir_frame, text="Browse", command=self._browse_dir).pack(side=tk.RIGHT)

        # Distro List
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        ttk.Label(list_frame, text="Select Distributions:").pack(anchor=tk.W, pady=(0, 5))
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.listbox = tk.Listbox(list_frame, bg=self.sec_bg_color, fg=self.text_color, 
                                  selectbackground=self.accent_color, selectforeground=self.bg_color,
                                  borderwidth=0, highlightthickness=0, selectmode=tk.MULTIPLE,
                                  yscrollcommand=scrollbar.set, font=("Helvetica", 11), activestyle='none')
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.listbox.yview)

        for distro in sorted(DISTROS.keys()):
            self.listbox.insert(tk.END, distro)

        # Progress and Status
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(main_frame, textvariable=self.status_var, wraplength=450).pack(fill=tk.X, pady=(0, 5))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 20))

        # Action Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        self.verify_var = tk.BooleanVar(value=False)
        verify_chk = ttk.Checkbutton(btn_frame, text="Verify SHA256", variable=self.verify_var)
        verify_chk.pack(side=tk.LEFT, padx=(0, 10))

        self.download_btn = ttk.Button(btn_frame, text="Download Selected", command=self._start_download)
        self.download_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True)

    def _browse_dir(self):
        directory = filedialog.askdirectory(initialdir=self.dir_var.get())
        if directory:
            self.dir_var.set(directory)

    def _update_status(self, message):
        self.after(0, lambda: self.status_var.set(message))

    def _update_progress(self, percent, mb_down, mb_total):
        # Cap UI updates at ~10/s. Without this, a 4 GB ISO at 8 KB block size
        # would queue ~500k after() calls and freeze the UI. Always let 100%
        # through so the bar visibly fills at end-of-file.
        now = time.monotonic()
        if percent < 100 and (now - self._last_progress_emit) < 0.1:
            return
        self._last_progress_emit = now
        def ui_update():
            self.progress_var.set(percent)
            self.status_var.set(f"Downloading... {percent:.1f}% ({mb_down:.1f}/{mb_total:.1f} MB)")
        self.after(0, ui_update)

    def _start_download(self):
        selected_indices = self.listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select at least one distribution to download.")
            return

        dest_dir = Path(self.dir_var.get())
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Directory Error", f"Could not create directory:\n{e}")
            return

        selected_distros = [self.listbox.get(i) for i in selected_indices]
        verify_sha256 = bool(self.verify_var.get())

        self.download_btn.config(state=tk.DISABLED)
        self.listbox.config(state=tk.DISABLED)
        
        self.download_thread = threading.Thread(
            target=self._download_worker, 
            args=(selected_distros, dest_dir, verify_sha256),
            daemon=True
        )
        self.download_thread.start()

    def _download_worker(self, distros, dest_dir, verify_sha256=False):
        failures = []
        for distro in distros:
            self._update_status(f"Resolving URL for {distro}...")
            self.after(0, lambda: self.progress_var.set(0))
            # Reset the throttle so the first progress tick of each download
            # is emitted immediately rather than dropped.
            self._last_progress_emit = 0.0
            
            config = DISTROS[distro]
            download_url = None

            if config['type'] == 'direct':
                download_url = config['url']
            elif config['type'] == 'github':
                download_url = ScraperEngine.find_latest_github(config['repo'], self._update_status)
            elif config['type'] == 'regex':
                download_url = ScraperEngine.find_latest_via_regex(config, self._update_status)

            if download_url:
                ok = ScraperEngine.download_file(download_url, dest_dir, self._update_status, self._update_progress, verify_sha256=verify_sha256)
                if not ok:
                    failures.append((distro, "download failed"))
            else:
                self._update_status(f"Could not resolve download URL for {distro}")
                failures.append((distro, "URL not resolved"))
            
        succeeded = len(distros) - len(failures)
        if failures:
            summary = f"Done. {succeeded}/{len(distros)} succeeded. Failed: " + \
                      ", ".join(f"{name} ({reason})" for name, reason in failures)
        else:
            summary = f"All {succeeded} download(s) finished successfully."
        self._update_status(summary)
        self.after(0, lambda: self.download_btn.config(state=tk.NORMAL))
        self.after(0, lambda: self.listbox.config(state=tk.NORMAL))


if __name__ == "__main__":
    app = DistrohopperApp()
    app.mainloop()
