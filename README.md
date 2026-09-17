# Secure Wipe File

**Console-based secure free-space wiping tool for Windows** — prevents recovery of recently deleted files (emptied from Recycle Bin) via repeated overwrite of free disk space, with a retro MS-DOS style interface.

> ⚠️ **DISCLAIMER**
> This tool performs **irreversible overwrites** of free disk space. Once wiped, deleted data **cannot be recovered by any means**. Use entirely at your own risk and responsibility. The author assumes no liability for data loss resulting from use or misuse of this tool. Some EDR/antivirus software may flag this tool as suspicious due to its low-level disk write behavior — this is expected for any secure-erase utility.

---

## Features

- **Not a low-level format** — targets free/unallocated space only, so existing files and the OS are untouched.
- **Hybrid wipe method**:
  - File-fill overwrite (portable, no admin dependency for the core pass)
  - Raw sector overwrite of free clusters (requires Administrator privileges)
- **Automatic drive type detection** (HDD vs SSD), with method adapted per type:
  - **HDD** → 3-pass DoD 5220.22-M (short): `0x00` → `0xFF` → random + verify
  - **SSD** → TRIM + 1-pass random overwrite (to minimize wear)
- **Metadata trace cleanup**, beyond just free space:
  - VSS shadow copies
  - USN journal
  - Page file / hibernation file
  - Recent items & thumbnail cache
- **Drive enumeration & selection menu** — only fixed local drives are shown; network drives and removable (USB/external) drives are automatically skipped.
- **C:\ safety handling** — prioritizes the file-fill method over raw sector overwrite, reserves a minimum free-space safety floor, and writes in adaptive chunks with free-space checks (never fills disk to the point of hanging the system).
- **Static, in-place progress bar** per pass — fits within a single fixed console screen area (no scrolling).
- **Interrupted-process recovery** — detects and offers cleanup of leftover dummy files from a previous crashed/killed session on startup.
- **Concurrency guard** — lock file prevents two instances from targeting the same drive simultaneously.
- **Abort handling**:
  - Intentional `Ctrl+C` → finishes current chunk write, logs the abort event (pass number, % complete), then offers **stop + cleanup** or **continue**.
  - Unintentional interruption (crash/power loss) → detected at next startup via stale lock file / leftover dummy files, with a **discard + cleanup** option (no resume-from-checkpoint).
- **Full audit log** for compliance/auditing purposes — timestamp (start/end), target drive, method & pass count, per-item metadata cleanup result, and Windows username.
- **Admin elevation check** — exits with a clear error message if not run as Administrator (no automatic UAC prompt).

## Requirements

- Windows 10/11
- Python 3.x
- Administrator privileges (required for raw sector overwrite and metadata trace cleanup)

## Installation

```bash
git clone https://github.com/<penjagakres>/secure-wipe-file.git
cd secure-wipe-file
pip install -r requirements.txt
```

## Usage

Run from an **elevated** (Administrator) command prompt:

```bash
python main.py
```

On startup, the tool will:

1. Display version, author, and the disclaimer
2. Check for and offer cleanup of any leftover files from a previous interrupted session
3. Enumerate eligible fixed local drives
4. Prompt you to select which drive to wipe
5. Auto-detect drive type (HDD/SSD) and run the appropriate wipe method
6. Show a live, static progress bar per pass
7. Write a full audit log entry on completion

## Scope & Limitations

- Targets **free space only** — this is not a full-disk / low-level format tool.
- **BitLocker / disk-encryption handling is out of scope** for v1.
- No resume-from-checkpoint — an interrupted session must be discarded and restarted from the beginning.

## License

[MIT](LICENSE) — see the LICENSE file for details.

## Author

**Christian Prasetya**
Email: cprasetya@gmail.com
Version: 0.1
Created: 17 September 2026
