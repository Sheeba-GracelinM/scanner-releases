# RiskNox PII Scanner (native)

Standalone Windows app: one `RiskNoxScanner.exe`, no install and no .NET needed on the
target PC. Double-click opens the scanner window. The same exe also runs headless from the
command line for EDR/script deployment.

## Use

```
RiskNoxScanner.exe                          open the window
RiskNoxScanner.exe --gui D:\Share E:\Data   open the window with these folders preselected
RiskNoxScanner.exe --paths DIR [DIR..] [--role general|hr|finance] [--output report.json]
                   [--profile roles.json] [--samples] [--max-mb 50] [--cache cache.json]
                   [--workers N] [--throttle-ms 0] [--progress]
```

The JSON report has the same shape as `pii_scan.py`'s, so existing tooling keeps working.
UI errors are written to `%TEMP%\RiskNoxScanner_error.log`.

A Linux build with the same UI, CLI and engine is in `../RiskNoxScanner.Linux` (see its README).

## Build

Requires the .NET 10 SDK.

```
dotnet publish -c Release -o ..\dist      # -> dist\RiskNoxScanner.exe (self-contained, single file)
```

## Layout

| File | What |
|---|---|
| `Detectors.cs` | Patterns, checksums (Verhoeff, Luhn), confidence rules, scoring — a port of `pii_scan.py` |
| `Readers.cs` | Text, CSV/TSV, XLSX, DOCX, PPTX readers |
| `Pdf.cs` | PDF text + page rendering via PDFium; one engine copy per worker for real parallelism |
| `Ocr.cs` | Windows built-in OCR (`Windows.Media.Ocr`) for images and scanned PDFs |
| `Scanner.cs` | Parallel pipeline (enumerator → bounded channel → N workers), cache, report |
| `MainForm.cs`, `Widgets.cs`, `Theme.cs` | Native WinForms UI in the RiskNox theme |
| `Cli.cs` | Command-line scan (shared with the Linux build) |
| `Program.cs` | Entry point: window or CLI |

## Keeping results identical to the Python reference

Detection must match `pii_scan.py`. After changing either side:

```
python pii_scan.py --role hr --paths corpus --output ref.json
dist\RiskNoxScanner.exe --role hr --paths corpus --output new.json
python tools\parity.py ref.json new.json corpus        # must report 0 differences
```

`make_corpus.py` builds the accuracy corpus (with ground truth for `evaluate.py`);
`make_bench.py` builds a larger synthetic tree for speed tests.
