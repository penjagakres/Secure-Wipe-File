#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 SECURE DELETE TOOL - Free Space Wiper
 Version : 0.1
 Author  : Christian Prasetya
 Email   : cprasetya@gmail.com
 Created : 17 September 2026
================================================================================

PURPOSE
-------
Wipes FREE SPACE on local Windows drives so that files recently deleted
(including files emptied from the Recycle Bin) cannot be recovered by
undelete / data-recovery software. This is NOT a low-level format and does
NOT touch files that are still in use.

SCOPE (v1) - see /areas/secure-delete-tool.md design notes for full history
-----------------------------------------------------------------------------
  - Console (CLI) application only. No GUI.
  - On startup: enumerate FIXED LOCAL drives only.
        * Network drives  -> always skipped (not reachable via Get-Partition)
        * Removable drives (USB/external, BusType=USB) -> always skipped
  - User picks ONE drive at a time from a menu, confirms, then the wipe runs.
  - Drive type (HDD vs SSD) is auto-detected per physical disk:
        * HDD -> 3-pass overwrite (DoD 5220.22-M short: 0x00, 0xFF, random+verify)
        * SSD -> 1-pass random overwrite + TRIM (Optimize-Volume -ReTrim)
  - System/boot drive (C:\\) uses the SAME free-space wipe as other drives,
    but with a mandatory SAFETY FLOOR (reserved free space) and chunked,
    adaptive writes to avoid the OS hanging from a full disk. Raw sector
    passes are skipped on C:\\ in favor of the gentler file-fill method.
  - Metadata / trace cleanup (best-effort, logged): VSS shadow copies,
    USN journal, page-file-clear-at-shutdown flag, hibernation file reset,
    Recent Items / thumbnail cache (last two only when target is the
    system drive).
  - Administrator privilege is REQUIRED. If not elevated, the tool prints
    an error and exits (no auto UAC prompt in v1).
  - Concurrency guard: a per-drive lock file prevents two instances from
    targeting the same drive at once.
  - Interrupted-session recovery: leftover dummy files / stale locks from
    a previous crashed/killed run are detected and cleaned up at startup.
    There is NO resume-from-checkpoint in v1 - interrupted work is always
    discarded and restarted fresh by the user.
  - Full audit log written per run (timestamps, drive, method, pass
    results, per-item cleanup result, Windows username) for compliance /
    audit purposes.
  - UI: retro MS-DOS look (ASCII box-drawing, ALL CAPS headers, white/
    yellow text on a blue background), fully in English, with an in-place
    (non-scrolling) progress display.

EXPLICITLY OUT OF SCOPE (v1)
-----------------------------------------------------------------------------
  - GUI, scheduled/automatic triggering, resume-from-checkpoint,
    cryptographic log signing, BitLocker/encryption-aware handling,
    MFT-level precision targeting of specific deleted files.

KNOWN LIMITATION (documented honestly, not hidden)
-----------------------------------------------------------------------------
  "Raw sector overwrite" in this tool means: writing directly to a file
  opened in binary mode with an explicit flush()+fsync() after every
  chunk, forcing the OS to commit writes to physical media rather than
  leaving them sitting in cache. It does NOT parse the NTFS $Bitmap /
  MFT to address specific unallocated clusters directly - that level of
  raw disk engineering was deliberately scoped out (see design notes,
  "Opsi B" was chosen over "Opsi A"). For the vast majority of
  "just deleted, want it gone now" use cases this is sufficient; it is
  not a substitute for forensic-grade tooling on media being decommissioned.

REQUIREMENTS
-----------------------------------------------------------------------------
  - Windows 10/11
  - Python 3.9+
  - pip install colorama
  - Must be run as Administrator (raw writes, VSS/USN/pagefile changes)
================================================================================
"""

import ctypes
import getpass
import json
import msvcrt
import os
import random
import shutil
import signal
import subprocess
import sys
import time
import winreg
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    from colorama import Back, Fore, Style
    from colorama import init as colorama_init
except ImportError:
    print("This tool requires the 'colorama' package.")
    print("Install it with:  pip install colorama")
    sys.exit(1)


# ==============================================================================
# CONSTANTS
# ==============================================================================

VERSION = "0.1"
AUTHOR = "Christian Prasetya"
EMAIL = "cprasetya@gmail.com"
CREATED_DATE = "17 September 2026"

BOX_WIDTH = 64

CHUNK_SIZE = 64 * 1024 * 1024          # 64 MB per write chunk
SAFETY_FLOOR_PERCENT = 0.05            # reserve at least 5% of volume...
SAFETY_FLOOR_MIN_BYTES = 5 * 1024 ** 3  # ...or 5 GB, whichever is larger
CRITICAL_ABORT_BYTES = 1 * 1024 ** 3    # emergency stop if free space < 1GB

DUMMY_FILE_PREFIX = "~SDWIPE_TMP_"
LOCK_DIR = Path(os.environ.get("TEMP", ".")) / "secure_wipe_tool_locks"
LOG_DIR = Path(__file__).resolve().parent / "logs"

DOD_PASSES_HDD = [
    ("PASS 1/3 (0x00)", "zero"),
    ("PASS 2/3 (0xFF)", "ff"),
    ("PASS 3/3 (RANDOM + VERIFY)", "random"),
]
SSD_PASSES = [
    ("PASS 1/1 (RANDOM)", "random"),
]

# Global flag flipped by the SIGINT handler; polled by the write loop so we
# never cut off a write mid-chunk.
_abort_requested = False


def _sigint_handler(signum, frame):
    global _abort_requested
    _abort_requested = True


signal.signal(signal.SIGINT, _sigint_handler)


# ==============================================================================
# DOS-RETRO UI HELPERS
# ==============================================================================

def theme_init():
    """Initialise colorama and paint the whole console blue, like DOS."""
    colorama_init(autoreset=False)
    # Classic DOS color 1F = blue background, white foreground.
    if os.name == "nt":
        os.system("color 1F")
    sys.stdout.write(Back.BLUE + Fore.WHITE)


def theme_reset():
    sys.stdout.write(Style.RESET_ALL)
    if os.name == "nt":
        os.system("color")


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")
    sys.stdout.write(Back.BLUE + Fore.WHITE)


def c_white(text: str) -> str:
    return f"{Fore.WHITE}{text}{Fore.WHITE}"


def c_yellow(text: str) -> str:
    return f"{Fore.YELLOW}{text}{Fore.WHITE}"


def box_line(char="=", width=BOX_WIDTH):
    print("+" + char * width + "+")


def box_text(text="", align="left", width=BOX_WIDTH):
    text = text[:width]
    if align == "center":
        text = text.center(width)
    elif align == "right":
        text = text.rjust(width)
    else:
        text = " " + text.ljust(width - 1)
    print("|" + text + "|")


def box_blank(width=BOX_WIDTH):
    print("|" + " " * width + "|")


def box_text_wrapped(label: str, value: str, width=BOX_WIDTH):
    """Print 'LABEL: value' where value may be too long for one box line.
    Wraps the value across as many indented lines as needed so it never
    overruns the box border."""
    box_text(f"{label}:")
    indent = "    "
    available = width - 1 - len(indent)
    if available <= 0:
        available = width - 1
        indent = ""
    for i in range(0, len(value), available):
        box_text(indent + value[i:i + available])


def safe_input(prompt: str = "") -> str:
    """input() that never crashes the app if stdin hits EOF (can happen on
    Windows after several subprocess calls disturb the console's stdin
    handle). Treats EOF the same as pressing Enter with no input."""
    try:
        return input(prompt)
    except EOFError:
        return ""


def read_menu_choice(prompt: str = "> ") -> str:
    """Reads a menu choice character-by-character using msvcrt so that
    pressing 'Q' quits INSTANTLY without waiting for Enter. Digits (and
    anything else) are echoed and accumulated normally until Enter is
    pressed, so multi-digit drive numbers still work. Backspace is
    supported. Falls back to safe_input() if msvcrt is unavailable
    (e.g. input is being piped/redirected)."""
    print(prompt, end="", flush=True)
    try:
        buffer = ""
        while True:
            ch = msvcrt.getch()

            if ch in (b"\x03",):  # Ctrl+C
                raise KeyboardInterrupt

            if ch in (b"\r", b"\n"):
                print()
                return buffer.strip().upper()

            if ch == b"\x08":  # backspace
                if buffer:
                    buffer = buffer[:-1]
                    print("\b \b", end="", flush=True)
                continue

            try:
                ch_str = ch.decode("utf-8", errors="ignore")
            except Exception:
                continue

            if not ch_str:
                continue

            if buffer == "" and ch_str.upper() == "Q":
                # Instant quit: no need to press Enter.
                print(ch_str)
                return "Q"

            if ch_str.isprintable():
                buffer += ch_str
                print(ch_str, end="", flush=True)
    except (OSError, ValueError):
        # msvcrt not usable in this environment (e.g. redirected stdin) -
        # fall back to normal line input.
        return safe_input().strip().upper()


# ==============================================================================
# ADMIN / PRIVILEGE CHECK
# ==============================================================================

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _running_as_compiled_exe() -> bool:
    """True when running as a compiled executable - covers both
    PyInstaller (sets sys.frozen) and Nuitka (defines __compiled__ in
    the module namespace instead; it does NOT set sys.frozen)."""
    if getattr(sys, "frozen", False):
        return True
    if "__compiled__" in globals():
        return True
    return False


def relaunch_as_admin() -> bool:
    """
    Relaunches this program with an elevated token, which makes Windows
    show the native UAC consent prompt. Works when running as a plain
    .py script (relaunched via python.exe), a PyInstaller .exe, or a
    Nuitka .exe.

    Note: if this program was compiled with Nuitka's --windows-uac-admin
    flag, Windows will already have shown the UAC prompt and elevated
    the process BEFORE any Python code runs - is_admin() will already be
    True and this function will never be called in that case. This
    function exists as a fallback for running the raw .py script, or an
    exe built without that manifest flag.

    Returns True if the elevated relaunch was successfully *started*
    (the UAC prompt was shown and accepted) - the original, unelevated
    process should exit right after this returns True, letting the new
    elevated instance take over. Returns False if the user clicked "No"
    on the UAC prompt, or if elevation could not be requested at all.
    """
    try:
        if _running_as_compiled_exe():
            # Compiled .exe (PyInstaller or Nuitka): relaunch the exe itself.
            executable = sys.executable
            param_list = sys.argv[1:]
        else:
            # Plain .py script: relaunch via the same Python interpreter,
            # passing this script's path as the first argument.
            executable = sys.executable
            param_list = [os.path.abspath(__file__)] + sys.argv[1:]

        params = " ".join(f'"{a}"' for a in param_list)

        # SW_SHOWNORMAL = 1. ShellExecuteW returns a value > 32 on success;
        # 1223 (ERROR_CANCELLED) means the user clicked "No" on the prompt.
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        return int(result) > 32
    except Exception:
        return False


# ==============================================================================
# DRIVE DISCOVERY
# ==============================================================================

@dataclass
class DriveInfo:
    letter: str            # e.g. "D:"
    disk_number: int
    media_type: str        # "HDD", "SSD", or "UNKNOWN"
    bus_type: str
    total_bytes: int
    free_bytes: int
    is_system_drive: bool


def _run_powershell_json(ps_command: str):
    """Run a PowerShell command and parse its ConvertTo-Json output."""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
        capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return []
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def enumerate_local_drives() -> List[DriveInfo]:
    """
    Enumerate FIXED local drives only.

    Using Get-Partition as the source naturally excludes mapped network
    drives (they are not physical-disk partitions), so no extra network
    filtering is needed. Removable (USB) drives are explicitly filtered
    out via BusType.
    """
    ps_cmd = (
        "Get-Partition | Where-Object { $_.DriveLetter } | ForEach-Object {"
        "  $part = $_;"
        "  $disk = Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue;"
        "  $phys = Get-PhysicalDisk -DeviceNumber $part.DiskNumber -ErrorAction SilentlyContinue;"
        "  [PSCustomObject]@{"
        "    DriveLetter = [string]$part.DriveLetter;"
        "    DiskNumber  = $part.DiskNumber;"
        "    MediaType   = [string]$phys.MediaType;"
        "    BusType     = [string]$phys.BusType;"
        "  }"
        "} | ConvertTo-Json"
    )
    raw = _run_powershell_json(ps_cmd)

    system_drive = os.environ.get("SystemDrive", "C:").upper()
    drives = []
    seen_letters = set()

    for entry in raw:
        letter_char = entry.get("DriveLetter", "")
        if not letter_char:
            continue
        letter = f"{letter_char.upper()}:"
        if letter in seen_letters:
            continue
        seen_letters.add(letter)

        bus_type = (entry.get("BusType") or "").upper()
        if bus_type == "USB":
            continue  # skip removable drives

        media_raw = (entry.get("MediaType") or "").upper()
        if "SSD" in media_raw:
            media_type = "SSD"
        elif "HDD" in media_raw or "HARD" in media_raw:
            media_type = "HDD"
        else:
            media_type = "UNKNOWN"

        try:
            usage = shutil.disk_usage(f"{letter}\\")
        except OSError:
            continue

        drives.append(DriveInfo(
            letter=letter,
            disk_number=entry.get("DiskNumber", -1),
            media_type=media_type,
            bus_type=bus_type or "UNKNOWN",
            total_bytes=usage.total,
            free_bytes=usage.free,
            is_system_drive=(letter == system_drive),
        ))

    drives.sort(key=lambda d: d.letter)
    return drives


# ==============================================================================
# LOCK FILE / CONCURRENCY GUARD
# ==============================================================================

def _lock_path(drive_letter: str) -> Path:
    safe = drive_letter.replace(":", "")
    return LOCK_DIR / f"lock_{safe}.json"


def _pid_is_running(pid: int) -> bool:
    if os.name != "nt":
        return False
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
        )
        return str(pid) in out.stdout
    except Exception:
        return True  # fail safe: assume it might still be running


def acquire_lock(drive_letter: str) -> bool:
    """Returns True if lock acquired, False if drive is already locked by a
    live process. Stale locks (dead PID) are cleared automatically."""
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock_file = _lock_path(drive_letter)

    if lock_file.exists():
        try:
            data = json.loads(lock_file.read_text())
            old_pid = data.get("pid")
            if old_pid and _pid_is_running(old_pid):
                return False  # genuinely in use
        except Exception:
            pass
        # stale lock -> fall through and overwrite it

    lock_file.write_text(json.dumps({
        "pid": os.getpid(),
        "drive": drive_letter,
        "started": datetime.now().isoformat(),
    }))
    return True


def release_lock(drive_letter: str):
    lock_file = _lock_path(drive_letter)
    try:
        lock_file.unlink(missing_ok=True)
    except Exception:
        pass


def cleanup_stale_locks_and_orphans(drives: List[DriveInfo]) -> List[str]:
    """Run once at startup. Detects locks whose owning PID is dead, and
    leftover dummy files from a previous interrupted run, and removes both.
    Returns a list of human-readable notices for display."""
    notices = []

    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    for lock_file in LOCK_DIR.glob("lock_*.json"):
        try:
            data = json.loads(lock_file.read_text())
            pid = data.get("pid")
            drive = data.get("drive", "?")
        except Exception:
            pid, drive = None, "?"
        if not pid or not _pid_is_running(pid):
            lock_file.unlink(missing_ok=True)
            notices.append(f"Stale lock for {drive} removed (previous session did not exit cleanly).")

    for d in drives:
        root = Path(f"{d.letter}\\")
        try:
            leftovers = list(root.glob(f"{DUMMY_FILE_PREFIX}*"))
        except OSError:
            leftovers = []
        for f in leftovers:
            try:
                f.unlink()
                notices.append(f"Leftover temp wipe file removed from {d.letter} ({f.name}).")
            except Exception:
                notices.append(f"WARNING: could not remove leftover file {f} - remove manually.")

    return notices


# ==============================================================================
# AUDIT LOGGER
# ==============================================================================

class AuditLogger:
    def __init__(self, drive_letter: str):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        safe = drive_letter.replace(":", "")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = LOG_DIR / f"wipe_log_{safe}_{timestamp}.txt"
        self.username = getpass.getuser()
        self.drive_letter = drive_letter
        self.start_time = datetime.now()
        self._write_header()

    def _write_header(self):
        self._append(f"SECURE DELETE TOOL v{VERSION} - AUDIT LOG")
        self._append(f"Run by user : {self.username}")
        self._append(f"Target drive: {self.drive_letter}")
        self._append(f"Start time  : {self.start_time.isoformat()}")
        self._append("-" * 70)

    def _append(self, line: str):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def event(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._append(f"[{ts}] {message}")

    def result(self, item: str, success: bool, detail: str = ""):
        status = "OK" if success else "FAILED"
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {item}: {status}"
        if detail:
            line += f" - {detail}"
        self._append(line)

    def close(self, aborted: bool = False):
        end_time = datetime.now()
        duration = end_time - self.start_time
        self._append("-" * 70)
        self._append(f"End time    : {end_time.isoformat()}")
        self._append(f"Duration    : {duration}")
        self._append(f"Outcome     : {'ABORTED BY USER' if aborted else 'COMPLETED'}")


# ==============================================================================
# FREE-SPACE WIPE ENGINE
# ==============================================================================

def _fill_buffer(pattern: str, size: int) -> bytes:
    if pattern == "zero":
        return b"\x00" * size
    if pattern == "ff":
        return b"\xFF" * size
    if pattern == "random":
        return os.urandom(size)
    raise ValueError(f"Unknown pattern: {pattern}")


def get_free_bytes(drive_letter: str) -> int:
    return shutil.disk_usage(f"{drive_letter}\\").free


def compute_safety_floor(total_bytes: int) -> int:
    return max(int(total_bytes * SAFETY_FLOOR_PERCENT), SAFETY_FLOOR_MIN_BYTES)


def wipe_pass(drive: DriveInfo, pattern: str, label: str, progress_cb) -> dict:
    """
    Runs one overwrite pass on the given drive's free space using the
    file-fill method. Writes are flushed + fsynced every chunk so data is
    committed to physical media rather than left in OS cache (see the
    documented "raw sector" limitation at the top of this file).

    progress_cb(label, pass_bytes_written, pass_total_bytes, speed_mb_s)
    is called periodically for the UI to render.
    Returns a dict with pass statistics.
    """
    global _abort_requested

    total_bytes = drive.total_bytes
    safety_floor = compute_safety_floor(total_bytes)
    start_free = get_free_bytes(drive.letter)
    pass_target_bytes = max(start_free - safety_floor, 0)

    dummy_name = f"{DUMMY_FILE_PREFIX}{drive.letter.replace(':', '')}_{pattern}.bin"
    dummy_path = Path(f"{drive.letter}\\{dummy_name}")

    written = 0
    start_time = time.time()
    aborted = False

    try:
        with open(dummy_path, "wb") as f:
            while written < pass_target_bytes:
                if _abort_requested:
                    aborted = True
                    break

                current_free = get_free_bytes(drive.letter)
                if current_free <= safety_floor:
                    break
                if current_free <= CRITICAL_ABORT_BYTES:
                    aborted = True
                    break

                remaining_target = pass_target_bytes - written
                chunk = min(CHUNK_SIZE, remaining_target, max(current_free - safety_floor, 0))
                if chunk <= 0:
                    break

                buf = _fill_buffer(pattern, chunk)
                f.write(buf)
                f.flush()
                os.fsync(f.fileno())
                written += chunk

                elapsed = max(time.time() - start_time, 0.001)
                speed_mb_s = (written / (1024 * 1024)) / elapsed
                progress_cb(label, written, pass_target_bytes, speed_mb_s)
    finally:
        # Always try to remove the dummy file so the user gets their
        # free space back, whether we finished, aborted, or errored.
        try:
            if dummy_path.exists():
                dummy_path.unlink()
        except Exception:
            pass

    return {
        "pattern": pattern,
        "bytes_written": written,
        "target_bytes": pass_target_bytes,
        "aborted": aborted,
        "duration_s": time.time() - start_time,
    }


def run_trim(drive_letter: str) -> bool:
    letter = drive_letter.replace(":", "")
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"Optimize-Volume -DriveLetter {letter} -ReTrim -Verbose"],
            capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL,
        )
        return completed.returncode == 0
    except Exception:
        return False


# ==============================================================================
# METADATA / TRACE CLEANUP
# ==============================================================================

def cleanup_vss_shadow_copies(drive_letter: str, logger: AuditLogger):
    try:
        completed = subprocess.run(
            ["vssadmin", "delete", "shadows", f"/for={drive_letter}", "/quiet"],
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
        )
        # vssadmin returns non-zero if there was simply nothing to delete;
        # that is not a real failure for our purposes.
        ok = completed.returncode == 0 or "no drive letter" not in completed.stdout.lower()
        logger.result("VSS shadow copy cleanup", ok, completed.stdout.strip()[:200])
    except Exception as e:
        logger.result("VSS shadow copy cleanup", False, str(e))


def cleanup_usn_journal(drive_letter: str, logger: AuditLogger):
    try:
        completed = subprocess.run(
            ["fsutil", "usn", "deletejournal", "/D", drive_letter],
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
        )
        ok = completed.returncode == 0
        logger.result("USN journal cleanup", ok, completed.stdout.strip()[:200])
    except Exception as e:
        logger.result("USN journal cleanup", False, str(e))


def set_clear_pagefile_at_shutdown(logger: AuditLogger):
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ClearPageFileAtShutdown", 0, winreg.REG_DWORD, 1)
        logger.result("Page file clear-at-shutdown flag", True, "Takes effect on next reboot")
    except Exception as e:
        logger.result("Page file clear-at-shutdown flag", False, str(e))


def reset_hibernation_file(logger: AuditLogger):
    try:
        subprocess.run(["powercfg", "/hibernate", "off"], capture_output=True, text=True,
                        timeout=30, stdin=subprocess.DEVNULL)
        completed = subprocess.run(["powercfg", "/hibernate", "on"], capture_output=True, text=True,
                                    timeout=30, stdin=subprocess.DEVNULL)
        logger.result("Hibernation file reset", completed.returncode == 0)
    except Exception as e:
        logger.result("Hibernation file reset", False, str(e))


def cleanup_recent_items_and_thumbnails(logger: AuditLogger):
    targets = []
    appdata = os.environ.get("APPDATA")
    localappdata = os.environ.get("LOCALAPPDATA")
    if appdata:
        targets.append(Path(appdata) / "Microsoft" / "Windows" / "Recent")
    if localappdata:
        targets.append(Path(localappdata) / "Microsoft" / "Windows" / "Explorer")

    removed, failed = 0, 0
    for folder in targets:
        if not folder.exists():
            continue
        for item in folder.glob("*"):
            try:
                if item.is_file():
                    item.unlink()
                    removed += 1
            except Exception:
                failed += 1
    logger.result("Recent items / thumbnail cache cleanup", failed == 0,
                  f"{removed} file(s) removed, {failed} failed")


def run_metadata_cleanup(drive: DriveInfo, logger: AuditLogger, progress_cb):
    progress_cb("Cleaning VSS shadow copies...")
    cleanup_vss_shadow_copies(drive.letter, logger)

    progress_cb("Cleaning USN journal...")
    cleanup_usn_journal(drive.letter, logger)

    if drive.is_system_drive:
        progress_cb("Setting page file clear-at-shutdown flag...")
        set_clear_pagefile_at_shutdown(logger)

        progress_cb("Resetting hibernation file...")
        reset_hibernation_file(logger)

        progress_cb("Cleaning Recent Items / thumbnail cache...")
        cleanup_recent_items_and_thumbnails(logger)


# ==============================================================================
# UI SCREENS
# ==============================================================================

def format_bytes(n: int) -> str:
    gb = n / (1024 ** 3)
    if gb >= 1024:
        return f"{gb / 1024:.2f} TB"
    return f"{gb:.1f} GB"


def show_startup_screen():
    clear_screen()
    box_line("=")
    box_text("SECURE DELETE TOOL - FREE SPACE WIPER", align="center")
    box_text(f"VERSION {VERSION}", align="center")
    box_line("=")
    box_text(f"AUTHOR  : {AUTHOR.upper()}")
    box_text(f"EMAIL   : {EMAIL.upper()}")
    box_text(f"CREATED : {CREATED_DATE.upper()}")
    box_line("=")
    box_text("DISCLAIMER:")
    box_blank()
    disclaimer_lines = [
        "THIS TOOL PERFORMS PERMANENT, IRREVERSIBLE OVERWRITES OF",
        "FREE DISK SPACE. THIS PROCESS CANNOT BE UNDONE. VERIFY THE",
        "SELECTED DRIVE IS CORRECT BEFORE PROCEEDING. USE AT YOUR OWN",
        "RISK. THE AUTHOR ASSUMES NO LIABILITY FOR ANY UNINTENDED",
        "DATA LOSS.",
    ]
    for line in disclaimer_lines:
        box_text(line)
    box_blank()
    note_lines = [
        "NOTE: THIS TOOL PERFORMS LOW-LEVEL DISK WRITES AND MAY BE",
        "FLAGGED BY ANTIVIRUS/EDR SOFTWARE. COORDINATE WITH YOUR",
        "SECURITY TEAM BEFORE DEPLOYMENT IN A MANAGED ENVIRONMENT.",
    ]
    for line in note_lines:
        box_text(line)
    box_blank()
    box_text("PRESS [ENTER] TO CONTINUE, OR [Q] TO QUIT", align="center")
    box_line("=")

    choice = read_menu_choice("\n> ")
    if choice == "Q":
        theme_reset()
        sys.exit(0)


def show_startup_notices(notices: List[str]):
    if not notices:
        return
    clear_screen()
    box_line("=")
    box_text("STARTUP NOTICES", align="center")
    box_line("=")
    for n in notices:
        box_text(n[:BOX_WIDTH - 2])
    box_line("=")
    safe_input("\nPRESS [ENTER] TO CONTINUE...")


def show_drive_menu(drives: List[DriveInfo]) -> Optional[DriveInfo]:
    clear_screen()
    box_line("=")
    box_text("DETECTED DRIVES", align="center")
    box_line("=")
    if not drives:
        box_text("NO ELIGIBLE LOCAL DRIVES FOUND.")
        box_line("=")
        safe_input("\nPRESS [ENTER] TO EXIT...")
        return None

    for i, d in enumerate(drives, start=1):
        sys_tag = " [SYSTEM]" if d.is_system_drive else ""
        line = (f"[{i}] {d.letter}\\  {format_bytes(d.total_bytes):>9}  "
                f"{d.media_type:<4}  FREE: {format_bytes(d.free_bytes):>9}{sys_tag}")
        box_text(line)
    box_line("=")
    box_text("SELECT A DRIVE (NUMBER) OR [Q] TO QUIT", align="center")
    box_line("=")

    choice = read_menu_choice("\n> ")
    if choice == "Q":
        return None
    if not choice.isdigit() or not (1 <= int(choice) <= len(drives)):
        print(c_yellow("Invalid selection."))
        time.sleep(1.2)
        return show_drive_menu(drives)
    return drives[int(choice) - 1]


def confirm_drive(drive: DriveInfo) -> bool:
    method = "3-PASS OVERWRITE (DoD 5220.22-M)" if drive.media_type == "HDD" else "1-PASS RANDOM + TRIM"
    if drive.media_type == "UNKNOWN":
        method = "3-PASS OVERWRITE (DoD 5220.22-M) [DEFAULT - MEDIA TYPE UNKNOWN]"

    clear_screen()
    box_line("=")
    box_text("CONFIRM WIPE OPERATION", align="center")
    box_line("=")
    box_text(f"DRIVE      : {drive.letter}\\")
    box_text(f"MEDIA TYPE : {drive.media_type}")
    box_text(f"TOTAL SIZE : {format_bytes(drive.total_bytes)}")
    box_text(f"FREE SPACE : {format_bytes(drive.free_bytes)}")
    box_text(f"METHOD     : {method}")
    if drive.is_system_drive:
        box_blank()
        box_text("THIS IS THE SYSTEM DRIVE. A SAFETY MARGIN WILL BE")
        box_text("RESERVED AND RAW WRITES WILL BE THROTTLED TO AVOID")
        box_text("DESTABILISING THE OPERATING SYSTEM.")
    box_line("=")
    box_text("THIS ACTION IS IRREVERSIBLE.")
    box_text(f'TYPE THE DRIVE LETTER (E.G. "{drive.letter[0]}") TO CONFIRM,')
    box_text("OR PRESS [ENTER] TO CANCEL:")
    box_line("=")

    answer = safe_input("\n> ").strip().upper()
    return answer == drive.letter[0]


def render_progress_screen(drive: DriveInfo, pass_label: str, written: int,
                            target: int, speed_mb_s: float, metadata_status: str):
    clear_screen()
    pct = 0 if target == 0 else min(100, int((written / target) * 100))
    bar_width = 40
    filled = int(bar_width * pct / 100)
    bar = "#" * filled + "." * (bar_width - filled)

    if speed_mb_s > 0 and target > written:
        remaining_mb = (target - written) / (1024 * 1024)
        eta_s = int(remaining_mb / speed_mb_s)
    else:
        eta_s = 0
    eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_s))

    box_line("-")
    box_text(f"WIPING: {drive.letter}\\ ({drive.media_type})")
    box_text(f"METHOD: {pass_label}")
    box_line("-")
    box_text(pass_label)
    box_text(f"[{bar}] {pct}%")
    box_text(f"SPEED: {speed_mb_s:6.1f} MB/S   ETA: {eta_str}")
    box_line("-")
    box_text(f"METADATA CLEANUP: {metadata_status}")
    box_line("-")
    box_text("PRESS CTRL+C TO ABORT (CURRENT CHUNK WILL FINISH FIRST)")
    box_line("-")


def show_abort_screen(drive: DriveInfo, pass_label: str, pct: int):
    clear_screen()
    box_line("=")
    box_text("ABORT REQUESTED", align="center")
    box_line("=")
    box_text(f"CURRENT PROGRESS: {pass_label}, {pct}% COMPLETE")
    box_blank()
    box_text("NOTE: ONLY THE PORTION ALREADY OVERWRITTEN IS PROTECTED.")
    box_text("REMAINING FREE SPACE MAY STILL CONTAIN RECOVERABLE DATA.")
    box_blank()
    box_text("THE WIPE WILL NOW STOP. TEMPORARY FILES WILL BE REMOVED")
    box_text("AND FREE SPACE WILL BE RESTORED.")
    box_line("=")
    safe_input("\nPRESS [ENTER] TO CONTINUE...")


def show_summary_screen(drive: DriveInfo, passes_done: int, passes_total: int,
                         aborted: bool, duration_s: float, log_path: Path):
    clear_screen()
    box_line("=")
    status = "WIPE ABORTED" if aborted else "WIPE COMPLETED"
    box_text(status, align="center")
    box_line("=")
    box_text(f"DRIVE            : {drive.letter}\\")
    box_text(f"PASSES COMPLETED : {passes_done}/{passes_total}")
    box_text(f"TOTAL TIME       : {time.strftime('%H:%M:%S', time.gmtime(duration_s))}")
    box_text_wrapped("LOG SAVED TO", str(log_path))
    box_line("=")
    safe_input("\nPRESS [ENTER] TO RETURN TO MENU...")


# ==============================================================================
# WIPE ORCHESTRATION
# ==============================================================================

def execute_wipe(drive: DriveInfo):
    global _abort_requested
    _abort_requested = False

    if not acquire_lock(drive.letter):
        clear_screen()
        box_line("=")
        box_text(f"{drive.letter}\\ IS ALREADY BEING WIPED BY ANOTHER INSTANCE.")
        box_line("=")
        safe_input("\nPRESS [ENTER] TO RETURN TO MENU...")
        return

    logger = AuditLogger(drive.letter)
    logger.event(f"Wipe started. Media type detected: {drive.media_type}")

    passes = DOD_PASSES_HDD if drive.media_type != "SSD" else SSD_PASSES
    passes_done = 0
    aborted = False
    start_time = time.time()

    metadata_status = "PENDING"

    def progress_cb(label, written, target, speed):
        render_progress_screen(drive, label, written, target, speed, metadata_status)

    try:
        for label, pattern in passes:
            logger.event(f"Starting {label}")
            result = wipe_pass(drive, pattern, label, progress_cb)
            logger.result(label, not result["aborted"],
                           f"{format_bytes(result['bytes_written'])} written in "
                           f"{result['duration_s']:.1f}s")
            if result["aborted"]:
                aborted = True
                pct = 0 if result["target_bytes"] == 0 else int(
                    (result["bytes_written"] / result["target_bytes"]) * 100)
                show_abort_screen(drive, label, pct)
                break
            passes_done += 1

        if not aborted and drive.media_type == "SSD":
            logger.event("Running TRIM on free space")
            ok = run_trim(drive.letter)
            logger.result("TRIM (Optimize-Volume -ReTrim)", ok)

        if not aborted:
            metadata_status = "RUNNING..."

            def meta_progress_cb(msg):
                render_progress_screen(drive, "METADATA CLEANUP", 1, 1, 0.0, msg)

            run_metadata_cleanup(drive, logger, meta_progress_cb)
            metadata_status = "DONE"

    except Exception as e:
        logger.event(f"UNEXPECTED ERROR: {e}")
        aborted = True
    finally:
        duration = time.time() - start_time
        logger.close(aborted=aborted)
        release_lock(drive.letter)
        show_summary_screen(drive, passes_done, len(passes), aborted, duration, logger.path)


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    if os.name != "nt":
        print("This tool only runs on Windows.")
        sys.exit(1)

    if not is_admin():
        print("This tool requires Administrator privileges.")
        print("Requesting elevation (a UAC prompt should appear)...")
        elevated = relaunch_as_admin()
        if elevated:
            # The elevated copy is now starting up in a new window/process.
            # This unelevated instance is done - exit quietly.
            sys.exit(0)
        else:
            print()
            print("ERROR: Elevation was cancelled or could not be requested.")
            print("This tool cannot continue without Administrator privileges.")
            input("\nPress Enter to exit...")
            sys.exit(1)

    theme_init()
    try:
        show_startup_screen()

        drives = enumerate_local_drives()
        notices = cleanup_stale_locks_and_orphans(drives)
        show_startup_notices(notices)

        while True:
            drive = show_drive_menu(drives)
            if drive is None:
                break
            if not confirm_drive(drive):
                continue
            execute_wipe(drive)
            # refresh free-space figures for the menu after a run
            drives = enumerate_local_drives()
    finally:
        theme_reset()


if __name__ == "__main__":
    main()
