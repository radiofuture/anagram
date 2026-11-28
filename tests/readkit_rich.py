"""Larger fixture files for the reading view: a finding as a
research group shares it, with a paper (PDF), a slide deck (PDF and PPTX), a
figure, a data table, a notebook, a Word document with a table, notes, and a
source file. Valid files, made with the standard library and the libraries in
the dependencies. The browser test and a person who looks at the view use
them; the text is made up."""

from __future__ import annotations

import base64
import io
import json
import math
import random
import textwrap
import zipfile

from readkit import _R, _W

from anagram.sim.writers import png_bytes, pptx_bytes

# ------------------------------------------------------------------- PDF


def _pdf_text(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf(pages: list[bytes], size: tuple[int, int]) -> bytes:
    """A valid PDF with the standard fonts F1 (Helvetica), F2 (Times), F3
    (Helvetica bold). `pages` are content streams."""
    w, h = size
    objs: list[bytes] = []
    n = len(pages)
    kids = " ".join(f"{6 + 2 * i} 0 R" for i in range(n))
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(f"<< /Type /Pages /Kids [{kids}] /Count {n} >>".encode())
    objs.append(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )
    objs.append(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman /Encoding /WinAnsiEncoding >>"
    )
    objs.append(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    )
    for i, content in enumerate(pages):
        objs.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w} {h}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
            f"/Contents {7 + 2 * i} 0 R >>".encode()
        )
        objs.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for num, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


class _Page:
    def __init__(self, width: int, height: int, margin: int = 72) -> None:
        self.ops: list[str] = []
        self.w, self.h, self.m = width, height, margin
        self.y = height - margin

    def text(
        self, s: str, font: str = "F2", size: float = 11, lead: float = 1.45, x=None, wrap=None
    ):
        width = wrap or int((self.w - 2 * self.m) / (size * 0.47))
        for line in textwrap.wrap(s, width) or [""]:
            self.y -= size * lead
            self.ops.append(
                f"BT /{font} {size} Tf {x or self.m} {self.y:.1f} Td ({_pdf_text(line)}) Tj ET"
            )

    def gap(self, n: float) -> None:
        self.y -= n

    def bars(self, values: list[float], height: int = 150, label: str = "") -> None:
        x0, base = self.m + 30, self.y - height
        span = self.w - 2 * self.m - 40
        bw = span / (len(values) * 1.6)
        top = max(values)
        self.ops.append("0.16 0.25 0.66 rg")
        for i, v in enumerate(values):
            bh = (height - 20) * v / top
            self.ops.append(f"{x0 + i * bw * 1.6:.1f} {base:.1f} {bw:.1f} {bh:.1f} re f")
        self.ops.append("0 0 0 rg 0.6 w")
        self.ops.append(f"{x0 - 6:.1f} {base:.1f} m {x0 + span:.1f} {base:.1f} l S")
        self.ops.append(f"{x0 - 6:.1f} {base:.1f} m {x0 - 6:.1f} {base + height:.1f} l S")
        self.y = base - 6
        if label:
            self.text(label, "F1", 9)

    def curve(self, height: int = 150) -> None:
        x0, base = self.m + 30, self.y - height
        span = self.w - 2 * self.m - 40
        pts = [
            (x0 + span * t / 60, base + height * (0.1 + 0.8 / (1 + math.exp(-(t - 30) / 6))))
            for t in range(61)
        ]
        path = " ".join(f"{x:.1f} {y:.1f} {'m' if i == 0 else 'l'}" for i, (x, y) in enumerate(pts))
        self.ops.append(f"0.88 0.27 0.16 RG 2 w {path} S 0 0 0 RG 0.6 w")
        self.ops.append(f"{x0 - 6:.1f} {base:.1f} m {x0 + span:.1f} {base:.1f} l S")
        self.ops.append(f"{x0 - 6:.1f} {base:.1f} m {x0 - 6:.1f} {base + height:.1f} l S")
        self.y = base - 6

    def bytes(self) -> bytes:
        return "\n".join(self.ops).encode("latin-1")


LOREM = (
    "We grew the cells in a standard medium at 37 degrees and counted them every six hours. "
    "The growth rate in the treated group was two times the rate in the control group from the "
    "second day. The effect stayed when we changed the batch of the medium, and it went away "
    "when we removed the treatment on day four."
)


def paper_pdf(pages: int = 3) -> bytes:
    out = []
    for n in range(pages):
        p = _Page(612, 792)
        if n == 0:
            p.text("Growth of treated cells doubles at 37 degrees", "F3", 18, wrap=48)
            p.text("A. Chen, R. Okafor, M. Silva  -  Northbridge University", "F1", 10)
            p.gap(14)
            p.text("Abstract", "F3", 11)
            p.text(LOREM + " " + LOREM, "F2", 11)
            p.gap(10)
            p.text("1  Introduction", "F3", 12)
            p.text(LOREM, "F2", 11)
            p.gap(12)
            p.bars([3, 4, 6, 9, 13, 18, 22, 25], label="Figure 1. Cell count by day (thousands).")
        else:
            p.text(f"{n + 1}  {'Methods' if n == 1 else 'Results'}", "F3", 12)
            p.text(LOREM + " " + LOREM, "F2", 11)
            p.gap(12)
            p.curve()
            p.text(f"Figure {n + 1}. Fraction of cells in growth phase.", "F1", 9)
            p.gap(10)
            p.text(LOREM, "F2", 11)
        p.ops.append(f"BT /F1 9 Tf 300 40 Td ({n + 1}) Tj ET")
        out.append(p.bytes())
    return _pdf(out, (612, 792))


def deck_pdf(slides: int = 4) -> bytes:
    titles = ["Growth doubles at 37 degrees", "What we did", "What we saw", "What we do next"]
    out = []
    for n in range(slides):
        p = _Page(960, 540, margin=64)
        p.ops.append("0.91 0.91 0.95 rg 0 0 960 540 re f 0 0 0 rg")
        p.gap(20)
        p.text(titles[n % len(titles)], "F1", 34, wrap=40)
        p.gap(16)
        if n == 2:
            p.bars([4, 7, 12, 20, 26], height=230)
        else:
            for line in (
                "Cells grew two times faster with the treatment",
                "The effect stayed with a new batch of medium",
                "It went away when we removed the treatment",
            ):
                p.text("-  " + line, "F1", 20)
        out.append(p.bytes())
    return _pdf(out, (960, 540))


# ----------------------------------------------------------------- others


def figure_png(width: int = 640, height: int = 400) -> bytes:
    """A grey micrograph: noise with bright round cells."""
    rng = random.Random(7)  # noqa: S311 - fixture data
    px = bytearray(width * height)
    for i in range(width * height):
        px[i] = 70 + rng.randint(-18, 18)
    for _ in range(90):
        cx, cy, r = rng.randrange(width), rng.randrange(height), rng.randint(6, 16)
        for y in range(max(0, cy - r), min(height, cy + r + 1)):
            for x in range(max(0, cx - r), min(width, cx + r + 1)):
                d = (x - cx) ** 2 + (y - cy) ** 2
                if d <= r * r:
                    px[y * width + x] = min(255, 150 + int(90 * (1 - d / (r * r))))
    return png_bytes(width, height, bytes(px), {"Title": "Treated cells, day 3"})


def bars_png(width: int = 480, height: int = 280) -> bytes:
    px = bytearray(b"\xff" * (width * height))
    vals = [0.2, 0.3, 0.45, 0.6, 0.72, 0.9]
    bw = width // (len(vals) * 2)
    for i, v in enumerate(vals):
        h = int((height - 30) * v)
        x0 = bw // 2 + i * bw * 2
        for y in range(height - 10 - h, height - 10):
            for x in range(x0, x0 + bw):
                px[y * width + x] = 60
    for x in range(width):
        px[(height - 10) * width + x] = 0
    return png_bytes(width, height, bytes(px), {})


def growth_csv(rows: int = 1204) -> bytes:
    rng = random.Random(3)  # noqa: S311 - fixture data
    lines = ["sample,group,day,count,rate,note"]
    for i in range(rows):
        group = "treated" if i % 2 else "control"
        day = i % 7
        count = int(1000 * (2 if group == "treated" else 1) ** (day / 3) + rng.randint(-40, 40))
        note = "medium batch B" if i % 11 == 0 else ""
        lines.append(f"S{i:04d},{group},{day},{count},{count / 1000:.3f},{note}")
    return ("\n".join(lines) + "\n").encode()


def methods_docx() -> bytes:
    def para(text: str, style: str | None = None) -> str:
        ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
        return f'<w:p>{ppr}<w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>'

    def cell(text: str) -> str:
        return f"<w:tc><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:tc>"

    rows = [
        ("Medium", "Batch", "Cells per well"),
        ("Standard", "A", "12,000"),
        ("Standard", "B", "11,800"),
        ("Low serum", "A", "6,400"),
    ]
    table = (
        "<w:tbl>"
        + "".join("<w:tr>" + "".join(cell(c) for c in r) + "</w:tr>" for r in rows)
        + "</w:tbl>"
    )
    body = "".join(
        [
            para("Methods", "Heading1"),
            para(
                "We used one cell line from the lab stock. Each well had the same start count. "
                "We changed the medium every second day and kept the plates at 37 degrees."
            ),
            para("Plates and media", "Heading2"),
            para("Table 1 gives the media and the cell counts at the start."),
            table,
            para("Counting", "Heading2"),
            para(
                "Two people counted each plate without the group labels. We used the mean of the two counts."
            ),
        ]
    )
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{_W}"><w:body>{body}</w:body></w:document>'
    types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/word/document.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
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
        zf.writestr("word/media/plate-map.png", bars_png(360, 200))
    return buf.getvalue()


def talk_pptx() -> bytes:
    return pptx_bytes(
        "Lab meeting",
        "Chen",
        [
            ("Growth doubles at 37 degrees", ["Lab meeting, 12 November", "A. Chen"]),
            (
                "What we did",
                [
                    "One cell line, two groups",
                    "Counts every six hours for seven days",
                    "Two people counted each plate",
                ],
            ),
            (
                "What we saw",
                [
                    "Treated cells grew two times faster",
                    "The effect stayed with a new batch of medium",
                ],
            ),
            (
                "Next steps",
                ["Repeat with a second cell line", "Share the counts with the Okafor lab"],
            ),
        ],
    )


def analysis_ipynb() -> bytes:
    def code(src, outputs=()):
        return {
            "cell_type": "code",
            "execution_count": 1,
            "metadata": {},
            "outputs": list(outputs),
            "source": src,
        }

    def image(png):
        return {
            "data": {"image/png": base64.b64encode(png).decode()},
            "metadata": {},
            "output_type": "display_data",
        }

    nb = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": "# Growth model\n\nWe fit a logistic curve to the counts of each group.",
            },
            code(
                "import pandas as pd\ncounts = pd.read_csv('growth.csv')\ncounts.groupby('group').count.mean()"
            ),
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": "## Fit\n\nThe treated group has a **higher rate**; see the plot.",
            },
            code("fit = logistic(counts)\nfit.plot(by='group')", [image(bars_png())]),
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": "The rate ratio is `2.03` (95% interval 1.81 to 2.27).",
            },
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return json.dumps(nb).encode()


NOTES_MD = b"""# Notes for the next run

The second run failed because the incubator stopped for **six hours** on day two.

## What to change

- Use the incubator in room 4.12
- Count at the same hour each day
- Write the batch of the medium on each plate

1. Thaw the cells on Monday
2. Plate them on Tuesday

> The effect must stay with a new batch. If it does not, we stop.

| Day | Treated | Control |
|---|---|---|
| 1 | 1,210 | 1,190 |
| 3 | 2,480 | 1,620 |
| 5 | 5,020 | 2,150 |

The protocol is at https://example.org/protocols/growth-v2 and the code is in `fit.py`.
"""

FIT_PY = b'''"""Fit a logistic curve to the cell counts."""

import math


def logistic(t, k, r, t0):
    return k / (1 + math.exp(-r * (t - t0)))


def fit(points, steps=2000, lr=1e-3):
    k, r, t0 = max(y for _, y in points), 0.5, 3.0
    for _ in range(steps):
        grad = [0.0, 0.0, 0.0]
        for t, y in points:
            err = logistic(t, k, r, t0) - y
            grad[1] += err * t
        r -= lr * grad[1] / len(points)
    return k, r, t0
'''


RICH = {
    "paper.pdf": paper_pdf,
    "talk-slides.pdf": deck_pdf,
    "cells-day3.png": figure_png,
    "growth.csv": growth_csv,
    "methods.docx": methods_docx,
    "lab-meeting.pptx": talk_pptx,
    "growth-model.ipynb": analysis_ipynb,
    "notes.md": lambda: NOTES_MD,
    "fit.py": lambda: FIT_PY,
    "raw-counts.h5": lambda: b"\x89HDF\r\n\x1a\n" + bytes(2048),
}
