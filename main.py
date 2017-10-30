#!/usr/bin/env python
# -*- coding = UTF-8 -*-
# authored by Osborne 2017-10-24
import pcapReader
import sys
import os

if __name__=="__main__":
    pkts_dir = sys.argv[1]
    out_file = sys.argv[2]
    for f in os.listdir(pkts_dir):
        file_dir = pkts_dir+"\\"+f
        print file_dir
        pcapReader.extract_attr_from_pcap(file_dir,out_file)
