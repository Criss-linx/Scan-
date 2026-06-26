
"""
Mass ICMP host scanner powered by masscan.


  • masscan has a custom async C TCP/IP stack — separate TX and RX threads,
    no GIL, no Python overhead, no shared-socket reply-theft between workers.
  • It can do 1.6M+ packets/sec on Linux bare metal.
  • --ping sends ICMP echo requests natively.
  • -iL reads a file of IPs directly — no chunking logic needed.
  • -oJ outputs clean JSON — trivial to parse into CSV.
  • Ctrl-C saves state to paused.conf and can be resumed with --resume.

Install:
  sudo apt install masscan          # Debian/Ubuntu
  brew install masscan              # macOS (Homebrew)
  # or build from source:
  # git clone https://github.com/robertdavidgraham/masscan && cd masscan && make

Usage:
  sudo python3 scan.py                        # default settings
  sudo python3 scan.py --rate 50000           # faster (careful on metered links)
  sudo python3 scan.py --input myips.txt      # custom input file
  sudo python3 scan.py --wait 5               # shorter wait after TX done
  sudo python3 scan.py --resume               # resume a paused scan
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile

# ─── CONFIG ──────────────────────────────────────────────────────────────────
INPUT_FILE   = "v4.addrs"   
OUTPUT_FILE  = "results.csv"
RATE         = 10000          # packets/sec
WAIT         = 10            # seconds to wait after TX completes for late replies
# ─────────────────────────────────────────────────────────────────────────────


def check_masscan():
    if not shutil.which("masscan"):
        sys.exit(
            "ERROR: masscan not found.\n"
            "Install it:\n"
            "  sudo apt install masscan        # Debian/Ubuntu\n"
            "  sudo yum install masscan        # RHEL/CentOS\n"
            "  brew install masscan            # macOS\n"
            "  https://github.com/robertdavidgraham/masscan  (build from source)"
        )


def check_root():
    if os.geteuid() != 0:
        sys.exit("ERROR: masscan requires root (raw socket access).\nRun with: sudo python3 scan.py")


def run_scan(input_file, rate, wait, resume=False):
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    out.close()

    if resume:
        cmd = ["masscan", "--resume", "paused.conf", "-oJ", out.name]
    else:
        cmd = [
            "masscan",
            "-iL", input_file,
            "--ping",             # ICMP echo requests
            "--rate", str(rate),
            "--wait", str(wait),
            "-oJ", out.name,
        ]

    print(f"Running: {' '.join(cmd)}")
    print("(Press Ctrl-C to pause — scan state saved to paused.conf and can be resumed)")
    print()

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\nScan paused.  Resume later with: sudo python3 scan.py --resume")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        sys.exit(f"masscan exited with error code {e.returncode}")

    return out.name


def resolve_output_path(output_csv, input_file):
    if os.path.isabs(output_csv):
        return output_csv

    input_path = os.path.abspath(input_file)
    input_dir = os.path.dirname(input_path) or os.getcwd()
    return os.path.join(input_dir, output_csv)


def parse_and_write(json_path, input_file, output_csv):
    output_csv = resolve_output_path(output_csv, input_file)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    print("Reading input IPs …")
    all_ips = set()
    with open(input_file, encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith("#"):
                all_ips.add(ip)

    print("Parsing masscan results …")
    alive = set()
    try:
        with open(json_path, encoding="utf-8") as f:
            raw = f.read().strip()
        if raw:
            raw = raw.rstrip(",\n")
            if not raw.startswith("["):
                raw = "[" + raw + "]"
            records = json.loads(raw)
            for rec in records:
                if isinstance(rec, dict) and "ip" in rec:
                    alive.add(str(rec["ip"]))
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(
            f"Warning: could not parse masscan JSON ({e}). "
            f"All IPs will be marked 'dead'. Check the raw file: {json_path}"
        )

    print(f"Writing {output_csv} …")
    alive_count = 0
    dead_count = 0
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "status"])
        for ip in sorted(all_ips, key=lambda x: tuple(int(o) for o in x.split("."))):
            if ip in alive:
                writer.writerow([ip, "alive"])
                alive_count += 1
            else:
                writer.writerow([ip, "dead"])
                dead_count += 1

    total = alive_count + dead_count
    print("Done!")
    print(f"  Total scanned : {total:,}")
    if total:
        print(f"  Alive         : {alive_count:,}  ({alive_count/total*100:.1f}%)")
    else:
        print(f"  Alive         : {alive_count:,} (0.0%)")
    print(f"  Dead          : {dead_count:,}")
    print(f"  Results       → {output_csv}")

    with open(output_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([])
        writer.writerow(["summary_type", "count", "percentage"])
        writer.writerow(["Total Scanned", total, "100%"])
        writer.writerow(["Alive", alive_count, f"{alive_count/total*100:.1f}%" if total else "0.0%"])
        writer.writerow(["Dead", dead_count, f"{dead_count/total*100:.1f}%" if total else "0.0%"])

    if os.path.exists(json_path):
        os.unlink(json_path)


def main():
    parser = argparse.ArgumentParser(description="ICMP host scanner via masscan")
    parser.add_argument("--input",  default=INPUT_FILE,  help="Input file of IPs (one per line)")
    parser.add_argument("--output", default=OUTPUT_FILE, help="Output CSV file")
    parser.add_argument("--rate",   default=RATE, type=int, help="Packets per second (default: 10000)")
    parser.add_argument("--wait",   default=WAIT, type=int, help="Seconds to wait after TX (default: 10)")
    parser.add_argument("--resume", action="store_true",    help="Resume a previously paused scan")
    args = parser.parse_args()

    check_masscan()
    check_root()

    json_path = run_scan(args.input, args.rate, args.wait, resume=args.resume)
    parse_and_write(json_path, args.input, args.output)


if __name__ == "__main__":
    main()