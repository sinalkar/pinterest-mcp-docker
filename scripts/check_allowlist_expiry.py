#!/usr/bin/env python3
"""Check expiry dates on entries in .trivyignore and .semgrepignore."""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

IGNORE_FILES = [".trivyignore", ".semgrepignore"]


def check_file(path: Path) -> list[str]:
    if not path.exists():
        return []

    errors = []
    today = datetime.date.today()

    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "# expires:" not in line:
            errors.append(f"{path}:{i}: Missing required comment format '# expires: YYYY-MM-DD'")
            continue

        try:
            date_str = line.split("# expires:")[1].strip().split()[0]
            exp_date = datetime.date.fromisoformat(date_str)
            if exp_date < today:
                errors.append(f"{path}:{i}: Ignore entry expired on {exp_date} (today is {today})")
        except Exception as e:
            errors.append(f"{path}:{i}: Invalid expiry date format: {e}")

    return errors


def main() -> None:
    all_errors = []
    root = Path(__file__).resolve().parent.parent
    for fname in IGNORE_FILES:
        all_errors.extend(check_file(root / fname))

    if all_errors:
        print("Allowlist Expiry Check Failed:", file=sys.stderr)
        for err in all_errors:
            print(f"  {err}", file=sys.stderr)
        sys.exit(1)

    print("All allowlist entries are valid and unexpired.")


if __name__ == "__main__":
    main()
