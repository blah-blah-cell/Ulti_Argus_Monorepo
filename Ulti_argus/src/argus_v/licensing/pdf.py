from __future__ import annotations

from dataclasses import dataclass


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


@dataclass(frozen=True)
class PdfDocument:
    content: bytes

    def write_to(self, path: str) -> None:
        with open(path, "wb") as handle:
            handle.write(self.content)


def text_to_pdf(text: str) -> PdfDocument:
    """Create a simple PDF from text.

    No external dependencies; intended for small agreements and export tooling.
    """

    lines = text.splitlines() or [""]

    font_size = 11
    leading = 14
    start_x = 50
    start_y = 800

    content_lines = ["BT", f"/F1 {font_size} Tf", f"{start_x} {start_y} Td"]
    for idx, line in enumerate(lines):
        escaped = _escape_pdf_text(line)
        content_lines.append(f"({escaped}) Tj")
        if idx != len(lines) - 1:
            content_lines.append(f"0 -{leading} Td")
    content_lines.append("ET")

    stream = ("\n".join(content_lines) + "\n").encode("utf-8")

    objects: list[bytes] = []

    def add(obj: str) -> int:
        objects.append(obj.encode("utf-8"))
        return len(objects)

    add("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    add("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    add(
        "3 0 obj\n"
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\n"
        "endobj\n"
    )
    add("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    objects.append(
        (
            f"5 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode("utf-8")
            + stream
            + b"endstream\nendobj\n"
        )
    )

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"

    offsets = [0]
    pdf = bytearray(header)
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("utf-8"))
    pdf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf.extend(f"{off:010d} 00000 n \n".encode("utf-8"))

    pdf.extend(
        (
            "trailer\n"
            f"<< /Size {len(offsets)} /Root 1 0 R >>\n"
            "startxref\n"
            f"{xref_start}\n"
            "%%EOF\n"
        ).encode("utf-8")
    )

    return PdfDocument(content=bytes(pdf))
