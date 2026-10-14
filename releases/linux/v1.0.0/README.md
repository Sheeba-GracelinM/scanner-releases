# RiskNox PII Scanner 1.0.0 — Linux

Prebuilt from commit `f1c3cf9` with `DPDPproduct/RiskNoxScanner.Linux/build.sh`.

| Package | Machine |
|---|---|
| `RiskNoxScanner-linux-x64.tar.gz` | 64-bit Intel/AMD PCs and servers |
| `RiskNoxScanner-linux-arm64.tar.gz` | 64-bit ARM (e.g. Graviton, Ampere, Raspberry Pi 64-bit OS) |

Check the download with `sha256sum -c SHA256SUMS`, then:

```
tar xzf RiskNoxScanner-linux-x64.tar.gz
cd linux-x64
./RiskNoxScanner                        # open the scanner window
./RiskNoxScanner --paths ~/Documents    # headless scan -> pii_report.json
./install.sh                            # optional: add to the application menu
```

No .NET install is needed. For OCR of images and scanned PDFs, install Tesseract
(`sudo apt install tesseract-ocr`). See `DPDPproduct/RiskNoxScanner.Linux/README.md` for details.
