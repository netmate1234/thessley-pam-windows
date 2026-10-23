"""A QR code as text, drawn with half-block characters so two QR rows fit in one terminal row."""

try:
    import qrcode
except ImportError:  # pragma: no cover - the service needs it; without it only the link is shown
    qrcode = None


def lines(text: str, border: int = 1) -> list[str]:
    """The QR code for `text` as terminal lines (light modules drawn as blocks, like `qrencode -t UTF8`)."""
    if qrcode is None:
        return []
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=border)
    q.add_data(text)
    q.make(fit=True)
    m = q.get_matrix()  # True = dark module, quiet zone included
    if len(m) % 2:
        m.append([False] * len(m[0]))
    out = []
    for y in range(0, len(m), 2):
        row = ""
        for top, bottom in zip(m[y], m[y + 1]):
            row += {(True, True): " ", (True, False): "▄", (False, True): "▀", (False, False): "█"}[(top, bottom)]
        out.append(row)
    return out


def bitmap_rows(text: str, border: int = 4) -> list[str]:
    """Return a QR matrix as 0/1 rows for native UI clients to paint as a bitmap."""
    if qrcode is None:
        return []
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=border)
    q.add_data(text)
    q.make(fit=True)
    return ["".join("1" if dark else "0" for dark in row) for row in q.get_matrix()]
