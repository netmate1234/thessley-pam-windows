#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
tool_prefix=${MINGW_PREFIX:-x86_64-w64-mingw32}
out_dir="$PWD/build"
mkdir -p "$out_dir"

"${tool_prefix}-windres" -O coff resources.rc -o "$out_dir/provider-res.o"
"${tool_prefix}-g++" \
  -std=c++17 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
  -include mingw_compat.h -shared -static -pthread \
  ThessleyCredential.cpp CSampleProvider.cpp Dll.cpp guid.cpp helpers.cpp provider_diag.cpp password_vault.cpp \
  "$out_dir/provider-res.o" samplev2credentialprovider.def \
  -lcredui -lole32 -loleaut32 -lshlwapi -lsecur32 -ladvapi32 -lgdi32 -lws2_32 -luuid -lcrypt32 \
  -o "$out_dir/ThessleyCredentialProvider.dll"

# The credential provider uses this native bitmap window on the secure logon
# desktop; text fields cannot render a reliably square/scannable QR.
"$(dirname "$PWD")/windows-logon-test/build.sh"
cp "$(dirname "$PWD")/windows-logon-test/build/ThessleySignInTest.exe" \
  "$out_dir/ThessleyQrViewer.exe"
