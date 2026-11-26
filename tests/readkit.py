"""Small fixture files for the reading copy tests (R5 step 5). Each builder
gives the bytes of a valid file with a known text. Standard library and the
libraries in the dependencies only."""

from __future__ import annotations

import base64
import io
import json
import zipfile
import zlib

from anagram.sim.writers import png_bytes, pptx_bytes

PNG = png_bytes(4, 2, bytes(range(8)), {"Title": "tiny"})


def pdf_bytes(text: str = "Cells grow at 37 degrees") -> bytes:
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    body = zlib.compress(content)
    head = b"<< /Length %d /Filter /FlateDecode >>" % len(body)
    return b"%PDF-1.4\n1 0 obj\n" + head + b"\nstream\n" + body + b"\nendstream\nendobj\n%%EOF\n"


def csv_bytes(rows: int = 3) -> bytes:
    lines = ["sample,value"] + [f"s{i},{i * 2}" for i in range(rows)]
    return ("\n".join(lines) + "\n").encode()


def xlsx_bytes(rows: int = 3) -> bytes:
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["gene", "count"])
    for i in range(rows):
        ws.append([f"g{i}", i])
    wb.create_sheet("Other").append(["not", "read"])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_R = "http://schemas.openxmlformats.org/package/2006/relationships"


def docx_bytes(heading: str = "Methods", text: str = "We grew the cells.") -> bytes:
    doc = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_W}"><w:body>'
        f'<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>{heading}</w:t></w:r></w:p>'
        f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/word/document.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{_R}"><Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
        'officeDocument" Target="word/document.xml"/></Relationships>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", doc)
        zf.writestr("word/media/image 1.png", PNG)
    return buf.getvalue()


def pptx_file() -> bytes:
    return pptx_bytes("Talk", "Chen", [("Results", ["Growth doubled"]), ("Next", ["More runs"])])


def ipynb_bytes() -> bytes:
    nb = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["# Analysis\n", "We fit a model."],
            },
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [
                    {
                        "data": {"image/png": base64.b64encode(PNG).decode()},
                        "metadata": {},
                        "output_type": "display_data",
                    }
                ],
                "source": "plot(x)",
            },
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return json.dumps(nb).encode()


ALL = {
    "paper.pdf": pdf_bytes,
    "figure.png": lambda: PNG,
    "data.csv": csv_bytes,
    "counts.xlsx": xlsx_bytes,
    "methods.docx": docx_bytes,
    "talk.pptx": pptx_file,
    "notes.md": lambda: b"# Notes\n\nThe second run failed.\n",
    "analysis.ipynb": ipynb_bytes,
}
