import argparse
import subprocess
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
import os

import pandas as pd


DARKFLOW_BIN = Path("./target/release/darkflow").resolve()


def process_pcap(pcap_file: Path, feature_type: str):
    csv_path = pcap_file.with_name(
        f"{feature_type}-{pcap_file.stem}.csv"
    )

    cmd = [
        str(DARKFLOW_BIN),
        "--header",
        "-f", feature_type,
        "-o", "csv",
        "--export-path", str(csv_path),
        "pcap",
        str(pcap_file)
    ]

    try:
        subprocess.run(cmd, check=True)
        return f"OK: {pcap_file}"
    except subprocess.CalledProcessError as e:
        return f"ERROR: {pcap_file} -> {e}"


def merge_csvs(base_dir: Path, feature_type: str):
    csv_files = [
        p for p in base_dir.rglob(f"{feature_type}-*.csv")
        if not p.name.endswith("-merged.csv")
    ]
    if not csv_files:
        print("No csv files found")
        return

    first = True
    total_rows = 0
    output_file = base_dir / f"{feature_type}-merged.csv"
    if output_file.exists():
        output_file.unlink()
    print(f"\nMerged csvs:")
    print(f"  file = {output_file}")
    print(f"  total_rows = {total_rows}")
    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file)
            rows = len(df)
            total_rows += rows
            print(f"  total_rows = {total_rows}")

            # Category name = csv directory name
            label = csv_file.parent.name
            df["label"] = label
            df.to_csv(
                output_file,
                mode="w" if first else "a",
                header=first,
                index=False,
            )

            first = False
            print(f"Loaded {csv_file} -> {label}")
        except Exception as e:
            print(f"Skip {csv_file}: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="PCAP dir (default: script directory), e.g. `./general_dataset/raw_ss_trojan_vless_vmess`"
    )
    parser.add_argument(
        "--feature-type",
        required=True,
        choices=["cic", "cidds", "darkflow", "lexnetflow", "nfstream", "rustiflow"],
        help="Feature type (cic, cidds, darkflow, lexnetflow, nfstream, rustiflow (NTLFlow))"
    )
    parser.add_argument(
        "--merge",
        action="store_true",
        help="Merge all generated csv files into one (default: False)",
    )
    args = parser.parse_args()

    base_dir = Path(args.base_dir).resolve()
    feature_type = args.feature_type
    merge = args.merge

    pcap_files = [
        p for p in base_dir.rglob("*")
        if p.suffix.lower() in [".pcap", ".pcapng"]
    ]
    print(f"[+] Found {len(pcap_files)} pcap files")

    cpus = os.cpu_count()
    assert cpus is not None
    # workers = cpus-1
    workers = max(1, cpus//2)
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(process_pcap, p, feature_type)
            for p in pcap_files
        ]

        for f in as_completed(futures):
            print(f.result())

    if merge:
        print("[+] Merging csv files...")
        merge_csvs(base_dir, feature_type)

    print("[!] ALl JOBS ARE FINISHED SUCCESSFULLY!")


if __name__ == "__main__":
    """
    nohup python gen_darkflow.py \
        --base-dir ./dataset_name \
        --feature-type darkflow \
        --merge \
        > gen_darkflow-dataset_name-darkflow.log 2>&1 &
    """
    main()
