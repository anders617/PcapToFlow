#!/usr/bin/env python3
"""pcap_to_flows.py"""

import argparse
from csv import DictWriter
import os
import matplotlib.pyplot as plt
import numpy as np
import dpkt
from flow_sorter import FlowSorter


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Visualizes packet flows and speed index results.")
    parser.add_argument("-r", "--read", type=argparse.FileType('rb'))
    parser.add_argument("-l", "--localhost")
    parser.add_argument("-o", "--output",
                        help="Directory to write output csv files to.")
    opts = parser.parse_args()

    print("Opening reader...")
    pcap = dpkt.pcapng.Reader(opts.read)

    flow_sorter = FlowSorter(localhost=opts.localhost)
    print("Sorting packets...")
    flow_sorter.sort(pcap)

    if not os.path.exists(opts.output):
        try:
            os.mkdir(opts.output)
        except IOError as e:
            print("Error creating directory: {}, {}".format(opts.output, e))

    flows = flow_sorter.flows()

    flow_row = {}
    flow_num = 0

    with open(os.path.join(opts.output, 'flows.csv'), 'w') as flows_file:
        flows_fields = ['id', 'start_time', 'end_time', 'duration',
                        'src_ip', 'src_port', 'dst_ip',
                        'dst_port', 'total_bytes', 'total_message_bytes',
                        'avg_inter_arrival_time', 'median_inter_arrival_time',
                        'std_inter_arrival_time',
                        'num_packets', 'src_names', 'dst_names']
        packet_fields = [
            'timestamp',
            'inter_arrival_time',
            'seq',
            'ack',
            'flag_CWR',
            'flag_ECE',
            'flag_URG',
            'flag_ACK',
            'flag_PSH',
            'flag_RST',
            'flag_SYN',
            'flag_FIN',
            'window_size',
            'urgent_pointer',
            'tcp_header_size',
            'tcp_payload_size',
            'ip_header_size',
            'ip_id',
            'ip_tos',
            'ip_df',
            'ip_mf',
            'ip_offset'
        ]
        flows_writer = DictWriter(flows_file, fieldnames=flows_fields)
        flows_writer.writeheader()
        flow_row = {}
        packet_row = {}
        for flow in sorted(flows.values(),
                           key=lambda flow: flow.first_timestamp()):
            flow_row['id'] = flow_num
            flow_row['src_ip'] = str(flow.src_host().ip_addr())
            flow_row['src_port'] = flow.src_host().port()
            flow_row['src_names'] = flow.src_host().original_names()
            flow_row['dst_ip'] = str(flow.dst_host().ip_addr())
            flow_row['dst_port'] = flow.dst_host().port()
            flow_row['dst_names'] = flow.dst_host().original_names()
            flow_row['total_bytes'] = flow.total_bytes()
            flow_row['total_message_bytes'] = flow.total_message_bytes()

            inter_arrival_times = flow.inter_arrival_times()
            timestamps = flow.timestamps()
            flow_row['avg_inter_arrival_time'] = inter_arrival_times.mean() if len(flow) > 1 else np.nan
            flow_row['median_inter_arrival_time'] = np.median(inter_arrival_times) if len(flow) > 1 else np.nan
            flow_row['std_inter_arrival_time'] = inter_arrival_times.std() if len(flow) > 1 else np.nan
            flow_row['start_time'] = timestamps[0]
            flow_row['end_time'] = timestamps[-1]
            flow_row['duration'] = timestamps[-1] - timestamps[0]
            flow_row['num_packets'] = len(flow)
            flows_writer.writerow(flow_row)
            with open(os.path.join(opts.output, 'flow_{}.csv'.format(flow_num)), 'w') as packets_file:
                packet_num = 0
                packet_writer = DictWriter(packets_file, packet_fields)
                packet_writer.writeheader()
                for timestamp, packet in flow:
                    packet_row['timestamp'] = timestamp
                    if packet_num == 0:
                        packet_row['inter_arrival_time'] = np.nan
                    else:
                        packet_row['inter_arrival_time'] = inter_arrival_times[packet_num - 1]
                    packet_row['seq'] = packet.data.seq
                    packet_row['ack'] = packet.data.ack
                    packet_row['flag_CWR'] = int(bool(packet.data.flags & dpkt.tcp.TH_CWR))
                    packet_row['flag_ECE'] = int(bool(packet.data.flags & dpkt.tcp.TH_ECE))
                    packet_row['flag_URG'] = int(bool(packet.data.flags & dpkt.tcp.TH_URG))
                    packet_row['flag_ACK'] = int(bool(packet.data.flags & dpkt.tcp.TH_ACK))
                    packet_row['flag_PSH'] = int(bool(packet.data.flags & dpkt.tcp.TH_PUSH))
                    packet_row['flag_RST'] = int(bool(packet.data.flags & dpkt.tcp.TH_RST))
                    packet_row['flag_SYN'] = int(bool(packet.data.flags & dpkt.tcp.TH_SYN))
                    packet_row['flag_FIN'] = int(bool(packet.data.flags & dpkt.tcp.TH_FIN))
                    packet_row['window_size'] = packet.data.win
                    packet_row['urgent_pointer'] = packet.data.urp
                    packet_row['tcp_payload_size'] = len(packet.data.data)
                    packet_row['tcp_header_size'] = len(packet.data) - len(packet.data.data)
                    packet_row['ip_header_size'] = packet.hl
                    packet_row['ip_id'] = packet.id
                    packet_row['ip_tos'] = packet.tos
                    packet_row['ip_df'] = packet.df
                    packet_row['ip_mf'] = packet.mf
                    packet_row['ip_offset'] = packet.offset
                    packet_writer.writerow(packet_row)
                    packet_num += 1
            flow_num += 1

    # plt_level = 0
    # key = next(iter(flows.keys()))
    # out_timestamps = flows[key].timestamps()
    # in_timestamps = flows[key.reversed()].timestamps()
    # for t in out_timestamps:
    #     plt.axvline(t, ymin=plt_level, ymax=plt_level + 1)
    # for t in in_timestamps:
    #     plt.axvline(t, ymin=plt_level, ymax=plt_level + 1)
    # for flow_id in flows:
    #     if not flows[flow_id].is_localhost_src():
    #         continue
    #     # plt.axvline(out_timestamps, ymin=plt_level, ymax=plt_level + 1)
    #     # plt.axvline(in_timestamps, ymin=plt_level, ymax=plt_level + 1)
    #     # plt.plot(out_timestamps, np.zeros_like(out_timestamps) + plt_level,
    #     #          '|', markersize=10)
    #     # plt.plot(in_timestamps, np.zeros_like(in_timestamps) + plt_level,
    #     #          '|', markersize=10)
    #     plt_level += 2
    # plt.show()


if __name__ == "__main__":
    main()
