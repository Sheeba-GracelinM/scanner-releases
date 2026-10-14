# RiskNox PII Scanner (Linux)

Linux build of the Windows scanner in `../RiskNoxScanner`. It ships as a single `RiskNoxScanner`
executable, with nothing to install and no .NET needed on the target machine. Run it with no
arguments to open the scanner window (same pages, theme, password gate, export and upload as on
Windows). The same executable also runs headless from a shell for EDR/script deployment.

## Use

```
./RiskNoxScanner                          open the window
./RiskNoxScanner --gui /srv/share ~/Data  open the window with these folders preselected
./RiskNoxScanner --paths DIR [DIR..] [--role general|hr|finance] [--output report.json]
                 [--profile roles.json] [--samples] [--max-mb 50] [--cache cache.json]
                 [--workers N] [--throttle-ms 0] [--progress]
```

The flags, console output and JSON report are the same as the Windows exe's. UI errors are written
to `/tmp/RiskNoxScanner_error.log`. If no display is available (`DISPLAY`/`WAYLAND_DISPLAY`), the
window cannot open; use `--paths` instead.

Optional: `./install.sh` adds a menu entry and copies the binary to `~/.local/bin`.

## Requirements on the target machine

- x86-64 or arm64 glibc-based Linux supported by .NET 10 (current Ubuntu, Debian, RHEL/Rocky/Alma, Fedora, SUSE, etc.)
- For the window: an X11 or XWayland session plus `fontconfig` (both are standard on desktops)
- For OCR (optional): `tesseract` (`apt install tesseract-ocr`, `dnf install tesseract`,
  `pacman -S tesseract tesseract-data-eng`). Without it, images and scanned PDFs are skipped with
  the same skip reasons Windows uses when its OCR engine is missing. Set `RISKNOX_TESSERACT` to choose
  the binary and `RISKNOX_OCR_LANG` (e.g. `eng+hin`) to choose the languages.

## What differs from Windows, and why

| Windows | Linux |
|---|---|
| WinForms UI | Avalonia UI with the same layout, colours, sizes and behaviour |
| Windows built-in OCR (`Windows.Media.Ocr`) | System Tesseract (`tesseract` command) |
| `pdfium.dll`, one copy per worker | `libpdfium.so`, one copy per worker (same parallel design) |
| "Show in Explorer" | "Show in file manager" (`org.freedesktop.FileManager1`, falls back to `xdg-open`) |
| Full scan = all fixed drives | Full scan = all fixed mounts (normally `/`); `/proc`, `/sys`, `/dev`, `/run` are never walked |
| `$recycle.bin` excluded | Desktop trash (`~/.local/share/Trash`, `.Trash-*`) excluded |
| Paths compared case-insensitively | Paths compared case-sensitively (Linux filesystems are) |
| Key in `%APPDATA%\RiskNox` | Key in `~/.config/RiskNox`, mode 600 |
| Known folders redirected to OneDrive | Known folders renamed via `xdg-user-dirs` are followed |

Detection, readers, pipeline, cache, scoring, report, CLI and upload are **the same source files**
as the Windows build (linked from `../RiskNoxScanner`: `Detectors.cs`, `Readers.cs`, `Scanner.cs`,
`Uploader.cs`, `Cli.cs`), so findings are identical on both platforms.

## Build

Requires the .NET 10 SDK.

```
./build.sh               # -> ../dist/linux-x64/RiskNoxScanner and ../dist/RiskNoxScanner-linux-x64.tar.gz
./build.sh linux-arm64
```

## Parity check

```
python make_corpus.py corpus
python pii_scan.py --role hr --paths corpus --output ref.json
dist/linux-x64/RiskNoxScanner --role hr --paths corpus --output new.json
python tools/parity.py ref.json new.json corpus        # must report 0 differences
```
