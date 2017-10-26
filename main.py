import pcapReader
import sys


def main():
    pkts_dir = sys.argv[1]
    out_file = sys.argv[2]
    for f in pkts_dir:
        file_dir = pkts_dir+"/"+f
        pcapReader.extract_attr_from_pcap(file_dir.out_file)
