"""CSV → text/PNG renderers for baseline comparison results.

`render_text_table` is dependency-free; it is the default used by the
evaluation scripts so they always produce something readable.
`plot_baseline_comparison_csv` is best-effort and uses matplotlib if it
is available — otherwise it writes a `.txt` placeholder.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Mapping


def render_text_table(rows: list[Mapping[str, object]], headers: list[str]) -> str:
    """Render rows as an ASCII table."""

    def _row(values: Iterable[object]) -> str:
        return " | ".join(f"{str(v):>14s}" for v in values)

    lines = [_row(headers), _row(["-" * 14 for _ in headers])]
    for r in rows:
        lines.append(_row([r.get(h, "") for h in headers]))
    return "\n".join(lines)


def _write_csv(rows: list[Mapping[str, object]], headers: list[str], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({h: r.get(h, "") for h in headers})


def plot_baseline_comparison_csv(
    rows: list[Mapping[str, object]],
    *,
    out_dir: Path,
    csv_name: str = "baselines.csv",
    image_name: str = "baselines.png",
) -> dict[str, Path]:
    """Write a CSV plus (optionally) a bar chart of TPR/FPR per baseline.

    Returns the paths actually produced.
    """

    headers = ["baseline", "tpr", "fpr", "latency_us", "n_messages"]
    csv_path = out_dir / csv_name
    _write_csv(rows, headers, csv_path)

    out: dict[str, Path] = {"csv": csv_path}
    try:
        import matplotlib  # type: ignore[import-not-found]

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore[import-not-found]

        names = [str(r["baseline"]) for r in rows]
        tprs = [float(r["tpr"]) for r in rows]
        fprs = [float(r["fpr"]) for r in rows]

        fig, ax = plt.subplots(figsize=(8, 4))
        x = range(len(names))
        ax.bar([i - 0.2 for i in x], tprs, width=0.4, label="TPR")
        ax.bar([i + 0.2 for i in x], fprs, width=0.4, label="FPR")
        ax.set_xticks(list(x))
        ax.set_xticklabels(names, rotation=20, ha="right")
        ax.set_ylim(0, 1)
        ax.set_ylabel("rate")
        ax.set_title("Baseline TPR vs. FPR")
        ax.legend()
        fig.tight_layout()
        png_path = out_dir / image_name
        fig.savefig(png_path)
        out["png"] = png_path
    except Exception:
        # matplotlib not available; leave a textual placeholder so the
        # results dir always contains something deterministic.
        placeholder = out_dir / (image_name + ".txt")
        placeholder.write_text(render_text_table(rows, headers))
        out["txt"] = placeholder

    return out
