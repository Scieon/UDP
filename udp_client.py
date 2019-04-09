import argparse
import ipaddress
import math
import socket
import threading

from packet import Packet

ACK = 1
window_size = 0
window_start = 0
buffered_packets = {}


def handle_get_directory(router_addr, router_port, server_addr, server_port, route):
    peer_ip = ipaddress.ip_address(socket.gethostbyname(server_addr))
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 1

    msg = 'get,' + route
    payload = msg.encode("utf-8")

    p = Packet(packet_type=0,
               seq_num=1,
               peer_ip_addr=peer_ip,
               peer_port=server_port,
               payload=payload)
    try:
        print('Requesting all files within directory: ' + args.route)
        conn.sendto(p.to_bytes(), (router_addr, router_port))
        conn.settimeout(timeout)
        response, sender = conn.recvfrom(1024)

        print('\n--------------------------------')
        p = Packet.from_bytes(response)
        print(p.payload.decode("utf-8"))

    except socket.timeout:
        print('No response after {}s'.format(timeout))
        handle_get_directory(args.routerhost, args.routerport, args.serverhost, args.serverport, args.route)
    finally:
        conn.close()


def handle_get_file(router_addr, router_port, server_addr, server_port, route):
    peer_ip = ipaddress.ip_address(socket.gethostbyname(server_addr))
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 1

    msg = 'get,' + route
    payload = msg.encode("utf-8")

    p = Packet(packet_type=0,
               seq_num=1,
               peer_ip_addr=peer_ip,
               peer_port=server_port,
               payload=payload)
    try:
        buffered_file = {}
        timeout = 2

        print('Sending request for file: ' + args.route)
        conn.sendto(p.to_bytes(), (router_addr, router_port))
        conn.settimeout(timeout)

        #  RESPONSE FROM SERVER
        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)

        if p.packet_type == ACK:
            buffered_file[p.seq_num] = p

        while p.packet_type != ACK:
            print('RECEVIED A PACKET!')
            print(p)
            conn.sendto(p.to_bytes(), sender)
            conn.settimeout(timeout)

            buffered_file[p.seq_num] = p

            response, sender = conn.recvfrom(1024)
            p = Packet.from_bytes(response)
            # print(p.payload.decode("utf-8"))
        print('RETRIEVED ALL PACKETS FOR FILE WITHIN CLIENT')

        print(buffered_file)
        print('\n--------------------------------')
        msg = ''
        for seq_num, packet in sorted(buffered_file.items()):
            msg += packet.payload.decode('utf-8')
        print(msg)

    except socket.timeout:
        print('No response after {}s'.format(timeout))
        handle_get_file(args.routerhost, args.routerport, args.serverhost, args.serverport, args.route)
    finally:
        conn.close()


def request_packet():
    pass


def make_POST_packets(router_addr, router_port, server_addr, server_port, arg_body, route):
    peer_ip = ipaddress.ip_address(socket.gethostbyname(server_addr))
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 1

    packets = []

    try:
        print('Sending request to write to file: ' + args.route)

        # body = "Hello World"
        body = "0zello WorldWorldWorldWorldWorldWorldWorldWweweweorldWorldWorldWorldWorldWorldWorldWorldWorldWweweweorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorlddWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorld09WorldWorldWorldWorlldWdWorldWorldWrldWrldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorlWorldWorldWorldWorldWorldWorldWorldWoWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWweweweorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorlddWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWor2ldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWo3rldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorld09WorldWorldWorldWorlldWdWorldWorldWrldWrldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorlWorldWorldWorldWorldWorldWorldWorldWoWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorlddWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorld09WorldWorldWorldWorlldWdWorldWorldWrldWrldWorldWorldWorldWorldWorldWodWorldWorldWorldWorldWorldWorldWorldWorlWorldWorldWorldWorldWorldWorldWorldWoWorldWorldWorldWorldWorldWorldWorldWorldWorldWorldWorld4"
        # body = arg_body

        payload = body.encode("utf-8")
        seq_num = 1

        # Creates packets also splits if needed
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

        global buffered_packets
        global window_size
        global window_start

        window_size = math.floor(len(packets) / 2)
        thread_list = []
        if window_size == 0:
            p = send_packet(router_addr, router_port, packets[0], len(packets))
            while p is None:
                p = send_packet(router_addr, router_port, packets[0], len(packets))
        else:
            while window_start < len(packets):
                for i in range(window_size):
                    # print('i: ' + str(i))
                    # print('window start: ' + str(window_start))
                    # print('Sending Packet: ' + str(i + window_start + 1))
                    if i + window_start < len(packets) and packets[i + window_start].seq_num not in buffered_packets:
                        print('Sending Packet: ' + str(i + window_start + 1))
                        send_packet(router_addr, router_port, packets[i + window_start], len(packets))
        # print("DONE!")
        # p.packet_type = 1
        # p.payload = route.encode("utf-8")
        # conn.sendto(p.to_bytes(), (router_addr, router_port))
        #
        # conn.settimeout(timeout)
        # print('Waiting for a ack response')
        # response, sender = conn.recvfrom(1024)
        # p = Packet.from_bytes(response)
        send_final_ack(router_addr, router_port, p, conn, route)

    except socket.timeout:
        print('No response after {}s'.format(timeout))
    finally:
        conn.close()


def send_final_ack(router_addr, router_port, p, conn, route):
    timeout = 2
    try:
        print("Sending final packet!")
        p.packet_type = 1
        p.payload = route.encode("utf-8")
        conn.sendto(p.to_bytes(), (router_addr, router_port))

        conn.settimeout(timeout)
        print('Waiting for a ack response')
        response, sender = conn.recvfrom(1024)
    except socket.timeout:
        print('No final response after {}s'.format(timeout))
        send_final_ack(router_addr, router_port, p, conn, route)
    finally:
        conn.close()


def send_packet(router_addr, router_port, packet, packet_length):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 2

    try:
        msg = packet.payload.decode("utf-8")
        conn.sendto(packet.to_bytes(), (router_addr, router_port))
        # print('Send "{}" to router'.format(msg))

        # Try to receive a response within timeout
        conn.settimeout(timeout)
        print('Waiting for a response')
        response, sender = conn.recvfrom(1024)

        p = Packet.from_bytes(response)
        # print('Router: ', sender)
        print('\nPacket: ', p)
        # print('Packet Type', p.packet_type)
        print('Sequence Number', p.seq_num)
        # print('Payload: ' + p.payload.decode("utf-8"))

        global window_start
        global window_size
        global buffered_packets

        try:
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
        except:
            print('Reached end of buffer')
        print('--------')
        return p

    except socket.timeout:
        print('No response after {}s'.format(timeout))
        print('\n')
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
parser.add_argument("--route", help="http route", default="/files/")
parser.add_argument("--body", help="http method", default="Hello World")

args = parser.parse_args()

# run_client(args.routerhost, args.routerport, args.serverhost, args.serverport)

if args.method == 'post':
    make_POST_packets(args.routerhost, args.routerport, args.serverhost, args.serverport, args.body, args.route)

if args.route != "/files/":
    args.route = "/files/" + args.route

if args.method == 'get' and '.txt' not in args.route:
    handle_get_directory(args.routerhost, args.routerport, args.serverhost, args.serverport, args.route)

if args.method == 'get' and '.txt' in args.route:
    handle_get_file(args.routerhost, args.routerport, args.serverhost, args.serverport, args.route)
