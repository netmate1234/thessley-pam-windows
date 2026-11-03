#!/usr/bin/env python3
"""Build the credential-provider tile from the existing Thessley app icon."""

from pathlib import Path
import struct

from PIL import Image


ROOT = Path(__file__).resolve().parent
def build_mark():
    # Preserve the established blue rounded-square, shield and key artwork.
    # Its transparent outer corners are part of the icon and must stay alpha 0.
    return Image.open(ROOT / "thessley.ico").convert("RGBA")


def save_tile_bitmap(mark):
    # Use the existing artwork at tile size without flattening its transparent
    # rounded corners onto a square background.
    tile = mark.resize((128, 128), Image.Resampling.LANCZOS)

    width, height = tile.size
    pixels = tile.tobytes()
    # Credential UI composites the tile as a premultiplied-alpha DIB.
    bgra = bytes(channel for red, green, blue, alpha in zip(pixels[0::4], pixels[1::4], pixels[2::4], pixels[3::4])
                 for channel in ((blue * alpha + 127) // 255,
                                (green * alpha + 127) // 255,
                                (red * alpha + 127) // 255,
                                alpha))
    image_size = len(bgra)
    header = struct.pack("<IiiHHIIiiII", 108, width, -height, 1, 32, 3,
                         image_size, 3780, 3780, 0, 0)
    masks = struct.pack("<IIIII", 0x00FF0000, 0x0000FF00, 0x000000FF,
                        0xFF000000, 0x73524742)
    color_data = struct.pack("<9iIII", *([0] * 9), 0, 0, 0)
    dib_header = header + masks + color_data
    file_header = struct.pack("<2sIHHI", b"BM", 14 + len(dib_header) + image_size,
                              0, 0, 14 + len(dib_header))
    (ROOT.parent / "windows-logon-provider" / "tileimage.bmp").write_bytes(file_header + dib_header + bgra)


if __name__ == "__main__":
    mark = build_mark()
    mark.save(ROOT / "thessley-mark.png", optimize=True)
    save_tile_bitmap(mark)
