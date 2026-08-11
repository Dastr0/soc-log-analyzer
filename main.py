"""SOC Log Analyzer — entry point CLI.

v0.0.1: kerangka awal. Parser per source masih dikerjakan.
"""

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="soc-log-analyzer",
        description="Analisa log multi-source untuk SOC (Elastic + Wazuh).",
    )
    parser.add_argument(
        "--source",
        choices=["wazuh", "fortigate", "cyberark"],
        help="Jenis log source yang mau dianalisa",
    )
    parser.add_argument(
        "--file",
        help="Path ke file log yang mau dianalisa",
    )
    args = parser.parse_args()

    if not args.source or not args.file:
        parser.print_help()
        sys.exit(1)

    print(f"[!] Parser untuk source '{args.source}' belum tersedia di v0.0.1.")
    print(f"    File yang dituju: {args.file}")


if __name__ == "__main__":
    main()
