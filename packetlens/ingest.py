import argparse
from pathlib import Path

from packetlens.database import create_database, insert_packets
from packetlens.parser import read_packets
from packetlens.flows import rebuild_flows

def main():
    parser = argparse.ArgumentParser(
        description="Import a PCAP capture into a new SQLite database."
    )
    parser.add_argument("capture", type=Path)
    parser.add_argument("database", type=Path)
    args = parser.parse_args()

    if not args.capture.is_file():
        parser.error(f"Capture not found: {args.capture}")

    if args.database.exists():
        parser.error(
            "Output database already exists. Choose a new filename."
        )

    create_database(args.database)
    count = insert_packets(args.database, read_packets(args.capture))
    flow_count = rebuild_flows(args.database)

    print(f"Imported {count} packets into {args.database}")
    print(f"Created {flow_count} flows")

if __name__ == "__main__":
    main()