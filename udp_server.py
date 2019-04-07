import argparse
import socket
import os

from packet import Packet

DATA = 0
ACK = 1
SYN = 2
SYN_ACK = 3
buffered_packets = {}


def run_server(port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        conn.bind(('', port))
        print('Echo server is listening at', port)
        while True:
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
                handle_client(conn, data, sender)

    finally:
        conn.close()


def handle_get_directories(conn, packet, sender):
    packet.seq_num += 1
    conn.sendto(packet.to_bytes(), sender)


def handle_client(conn, data, sender):
    try:
        p = Packet.from_bytes(data)

        # Last packet has been sent so client has sent ACK
        if p.packet_type == ACK:
            msg = ''
            for seq_num, packet in sorted(buffered_packets.items()):
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
            buffered_packets.update({p.seq_num: p})

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
