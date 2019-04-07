import argparse
import ipaddress
import math
import socket
import threading

from packet import Packet

window = []
window_start = 0
buffered_packets = {}


def make_POST_packets(router_addr, router_port, server_addr, server_port, method):
    peer_ip = ipaddress.ip_address(socket.gethostbyname(server_addr))
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 5

    packets = []

    try:
        body = "Hello World"
        body = "Hello WorldWorldWorldWorldWorldWorldWorldWweweweorldWorldWorldWorldWorldWorldWorldWorldWorldWweweweorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorlddWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorld09WorldWorldWorldWorlldWdWorldWorldWrldWrldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorlWorldWorldWorldWorldWorldWorldWorldWoWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWweweweorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorlddWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorld09WorldWorldWorldWorlldWdWorldWorldWrldWrldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorlWorldWorldWorldWorldWorldWorldWorldWoWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorlddWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorld09WorldWorldWorldWorlldWdWorldWorldWrldWrldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorlWorldWorldWorldWorldWorldWorldWorldWoWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorld"

        payload = body.encode("utf-8")

        seq_num = 1
        while len(payload) > 1012 or len(payload) > 0:
            msg = payload[0:1012]
            payload = payload[1012:]
            p = Packet(packet_type=0,
                       seq_num=seq_num,
                       peer_ip_addr=peer_ip,
                       peer_port=server_port,
                       payload=msg)

            seq_num += 1
            packets.append(p)

        print(len(packets))
        window_size = math.floor(len(packets) / 2)
        global window_start
        thread_list = []

        while window_start < len(packets):
            for i in range(window_size):
                thread = threading.Thread(target=send_packet, args=(router_addr, router_port, packets[i+window_start],))
                thread_list.append(thread)
                # thread.start()

            for t in thread_list:
                try:
                    t.start()
                except:
                    pass
            for t in thread_list:
                t.join()
            # t1 = threading.Thread(target=send_packet, args=(router_addr, router_port, packets[0],))
            # t2 = threading.Thread(target=send_packet, args=(router_addr, router_port, packets[1],))
            # t1.start()
            # t2.start()
            # t1.join()
            # t2.join()

            # for t in thread_list:
            #     t.join()
            # send_packet(router_addr, router_port, packets[window_start])
   
    except socket.timeout:
        print('No response after {}s'.format(timeout))
    finally:
        conn.close()


def send_packet(router_addr, router_port, packet):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 4

    try:
        msg = packet.payload.decode("utf-8")
        conn.sendto(packet.to_bytes(), (router_addr, router_port))
        # print('Send "{}" to router'.format(msg))

        # Try to receive a response within timeout
        conn.settimeout(timeout)
        print('Waiting for a response')
        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Router: ', sender)
        print('Packet: ', p)
        print('Packet Type', p.packet_type)
        print('Sequence Number', p.seq_num)
        # print('Payload: ' + p.payload.decode("utf-8"))

        global window_start

        if p.packet_type == 1:
            print('Received ack!')
            if p.seq_num not in buffered_packets:
                buffered_packets[p.seq_num] = p
                print('Buffering packet')
            if p.seq_num == window_start + 1:
                print('INCREASING WINDOW START')
                window_start += 1
                while window_start + 1 in buffered_packets:
                    print("Buffered packet already inside move window")
                    window_start += 1
        print('--------')

    except socket.timeout:
        print('No response after {}s'.format(timeout))
    finally:
        conn.close()


def run_client(router_addr, router_port, server_addr, server_port):
    peer_ip = ipaddress.ip_address(socket.gethostbyname(server_addr))
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 5
    try:
        # msg = "Hello WorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorlddWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorld09WorldWorldWorldWorlldWdWorldWorldWrldWrldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorlWorldWorldWorldWorldWorldWorldWorldWoWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorld"
        msg = "Hello World"
        p = Packet(packet_type=0,
                   seq_num=1,
                   peer_ip_addr=peer_ip,
                   peer_port=server_port,
                   payload=msg.encode("utf-8"))

        conn.sendto(p.to_bytes(), (router_addr, router_port))
        print('Send "{}" to router'.format(msg))

        # Try to receive a response within timeout
        conn.settimeout(timeout)
        print('Waiting for a response')
        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Router: ', sender)
        print('Packet: ', p)
        print('Payload: ' + p.payload.decode("utf-8"))

    except socket.timeout:
        print('No response after {}s'.format(timeout))
    finally:
        conn.close()


# Usage:
# python echoclient.py --routerhost localhost --routerport 3000 --serverhost localhost --serverport 8007

parser = argparse.ArgumentParser()
parser.add_argument("--routerhost", help="router host", default="localhost")
parser.add_argument("--routerport", help="router port", type=int, default=3000)

parser.add_argument("--serverhost", help="server host", default="localhost")
parser.add_argument("--serverport", help="server port", type=int, default=8007)

parser.add_argument("--method", help="http method", default="post")
parser.add_argument("--body", help="http method", default="Hello World")

args = parser.parse_args()

# run_client(args.routerhost, args.routerport, args.serverhost, args.serverport)
make_POST_packets(args.routerhost, args.routerport, args.serverhost, args.serverport, args.method)
