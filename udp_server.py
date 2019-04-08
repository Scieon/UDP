import argparse
import math
import socket
import os

from packet import Packet

DATA = 0
ACK = 1
SYN = 2
SYN_ACK = 3
buffered_post_packets = {}
buffered_file_packets = {}
window_start = 0
window_size = 0


def run_server(port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        conn.bind(('', port))
        print('Echo server is listening at', port)
        while True:
            global buffered_file_packets

            data, sender = conn.recvfrom(1024)

            p = Packet.from_bytes(data)
            rcvd_payload = p.payload.decode("utf-8")

            if rcvd_payload.split(',')[0] == 'get':
                filepath = rcvd_payload.split(',')[1]
                print('performing get in ' + filepath)

                # print all files in current directory
                if '.txt' not in filepath:
                    files = ""
                    for file in os.listdir('.' + filepath):
                        files += file + '\n'
                    p.payload = files.encode("utf-8")
                    handle_get_directories(conn, p, sender)
                else:
                    handle_get_file(conn, p, sender, filepath)
            else:
                handle_client(conn, data, sender)

    finally:
        conn.close()


def handle_get_directories(conn, packet, sender):
    packet.seq_num += 1
    conn.sendto(packet.to_bytes(), sender)


def handle_get_file(conn, packet, sender, filepath):
    f = open('./' + filepath, 'r')
    # print(f.read())
    global window_start
    global window_size

    msg = str(f.read())
    payload = msg.encode("utf-8")
    print(msg)
    seq_num = 1
    packets = []

    while len(msg) > 1012 or len(msg) > 0:
        msg = payload[0:1012]
        payload = payload[1012:]
        if len(msg) == 0:
            break

        p = Packet(packet_type=0,
                   seq_num=seq_num,
                   peer_ip_addr=packet.peer_ip_addr,
                   peer_port=packet.peer_port,
                   payload=msg)

        seq_num += 1
        packets.append(p)
    print(packets)
    window_size = math.floor(len(packets) / 2)
    window_start = 0
    thread_list = []

    if window_size == 0:
        send_single_final_pkt(conn, packets[0], sender)

    else:
        while window_start < len(packets):
            for i in range(window_size):
                print('Sending packet ' + str(i+window_size))
                p = send_file_packet(conn, packets[i+window_size], sender)
                print(p)
                if p == window_start:
                    window_start += 1
                    print(window_start)
    # conn.sendto(packet.to_bytes(), sender)


def send_single_final_pkt(conn, packet, sender):
    packet.packet_type = ACK
    conn.sendto(packet.to_bytes(), sender)
    print('SENT FINAL PACKET OUT...')


def send_file_packet(conn, packet, sender):
    global buffered_packets
    timeout = 4

    try:
        conn.sendto(packet.to_bytes(), sender)
        conn.settimeout(timeout)
        print('Waiting for a response')

        response, sender = conn.recvfrom(1024)
        return Packet.from_bytes(response)

    except socket.timeout:
        print('No packet received')
        pass


def handle_client(conn, data, sender):
    try:
        p = Packet.from_bytes(data)
        global buffered_post_packets

        # Last packet has been sent so client has sent ACK
        if p.packet_type == ACK:
            msg = ''
            for seq_num, packet in sorted(buffered_post_packets.items()):
                msg += packet.payload.decode("utf-8")

            filepath = p.payload.decode("utf-8")
            f = open('./files/' + filepath + '.txt', 'w+')
            f.write(msg)
            print('DONE ^^^^')

        else:
            p.packet_type = ACK
            print(p.packet_type)
            print("Router: ", sender)
            print("Packet: ", p)
            print("Payload: ", p.payload.decode("utf-8"))
            buffered_post_packets[p.seq_num] = p


        # How to send a reply.
        # The peer address of the packet p is the address of the client already.
        # We will send the same payload of p. Thus we can re-use either `data` or `p`.
        conn.sendto(p.to_bytes(), sender)

    except Exception as e:
        print("Error: ", e)


# Usage python udp_server.py [--port port-number]
parser = argparse.ArgumentParser()
parser.add_argument("--port", help="echo server port", type=int, default=8007)
args = parser.parse_args()
run_server(args.port)
