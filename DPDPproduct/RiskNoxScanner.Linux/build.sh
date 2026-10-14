#!/usr/bin/env bash
# Build the standalone Linux scanner: one self-contained executable, no .NET needed on the target.
#   ./build.sh                 -> ../dist/linux-x64/RiskNoxScanner  (+ RiskNoxScanner-linux-x64.tar.gz)
#   ./build.sh linux-arm64     -> ../dist/linux-arm64/RiskNoxScanner
# Requires the .NET 10 SDK.
set -euo pipefail
RID="${1:-linux-x64}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../dist/$RID"
rm -rf "$OUT"
dotnet publish "$HERE/RiskNoxScanner.Linux.csproj" -c Release -r "$RID" -o "$OUT"
rm -f "$OUT"/*.pdb
cp "$HERE/packaging/risknox-scanner.desktop" "$HERE/packaging/risknox.svg" "$HERE/packaging/install.sh" "$OUT/"
chmod +x "$OUT/RiskNoxScanner" "$OUT/install.sh"
tar -C "$OUT/.." -czf "$OUT/../RiskNoxScanner-$RID.tar.gz" "$RID"
echo "Built $OUT/RiskNoxScanner"
echo "Package $(cd "$OUT/.." && pwd)/RiskNoxScanner-$RID.tar.gz"
