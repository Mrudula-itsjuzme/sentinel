"""Capture a browser frame for the caption-led demo renderer.

Browser control is environment-specific, so this script accepts an existing
PNG exported from the local browser. It copies the supplied frame into the
demo package and fails loudly when no frame is available.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshot", type=Path, required=True)
    parser.add_argument("--rejected", type=Path)
    parser.add_argument("--approved", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "assets" / "sentinel-browser.png")
    args = parser.parse_args()
    if not args.screenshot.exists():
        raise SystemExit(f"Screenshot not found: {args.screenshot}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.screenshot, args.output)
    print(args.output)
    for source, name in ((args.rejected, "sentinel-rejected.png"), (args.approved, "sentinel-approved.png")):
        if source:
            if not source.exists():
                raise SystemExit(f"Screenshot not found: {source}")
            destination = ROOT / "assets" / name
            shutil.copyfile(source, destination)
            print(destination)


if __name__ == "__main__":
    main()
