#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
"${MINGW_PREFIX:-x86_64-w64-mingw32}-windres" -O coff resources.rc -o build/app-res.o
x86_64-w64-mingw32-g++ -std=c++17 -O2 -municode -mwindows -static -static-libgcc -static-libstdc++ -Wall -Wextra \
  ThessleySignInTest.cpp build/app-res.o -o build/ThessleySignInTest.exe \
  -lws2_32 -ladvapi32 -luser32 -lgdi32
cp build/ThessleySignInTest.exe build/ThessleyQrViewer.exe
