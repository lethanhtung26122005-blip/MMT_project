import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

# Packet types
START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16                    # 4 ints x 4 bytes
MAX_PAYLOAD = 1472 - HEADER_SIZE    # 1456 bytes of data per packet
TIMEOUT = 0.5                       # 500 ms retransmission timer
DEBUG = False


def log(*args):
    if DEBUG:
        print(*args, file=sys.stderr)
        sys.stderr.flush()


def build(header, payload):
    return header / payload if payload else header


def make_packet(ptype, seq_num, payload=b""):
    header = PacketHeader(type=ptype, seq_num=seq_num, length=len(payload))
    header.checksum = compute_checksum(build(header, payload))
    return bytes(build(header, payload))


def parse_packet(raw):
    """Return (header, payload) if the packet is valid, otherwise None."""
    if len(raw) < HEADER_SIZE:
        return None
    header = PacketHeader(raw[:HEADER_SIZE])
    payload = raw[HEADER_SIZE:HEADER_SIZE + header.length]
    received_checksum = header.checksum
    header.checksum = 0
    if compute_checksum(build(header, payload)) != received_checksum:
        return None
    header.checksum = received_checksum
    return header, payload


def recv_ack(sock, timeout):
    """Wait up to `timeout` seconds. Return the ACK's seq_num, or None
    if nothing arrived / the packet was corrupted / it was not an ACK."""
    ready, _, _ = select.select([sock], [], [], max(timeout, 0))
    if not ready:
        return None
    raw, _ = sock.recvfrom(2048)
    parsed = parse_packet(raw)
    if parsed is None:
        return None
    header, _ = parsed
    if header.type != ACK:
        return None
    return header.seq_num


def sender(receiver_ip, receiver_port, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest = (receiver_ip, receiver_port)

    # Read the whole message and split it into chunks. DATA seq_num: 1..total
    message = sys.stdin.buffer.read()
    chunks = [message[i:i + MAX_PAYLOAD] for i in range(0, len(message), MAX_PAYLOAD)]
    total = len(chunks)
    packets = {i + 1: make_packet(DATA, i + 1, chunk) for i, chunk in enumerate(chunks)}

    # ---- 1. START (seq 0), wait for ACK with seq 1 ----
    start_pkt = make_packet(START, 0)
    connected = False
    while not connected:
        sock.sendto(start_pkt, dest)
        deadline = time.time() + TIMEOUT
        while time.time() < deadline:
            if recv_ack(sock, deadline - time.time()) == 1:
                connected = True
                break

    # ---- 2. DATA with sliding window + cumulative ACK ----
    base = 1        # oldest unacknowledged seq_num
    next_seq = 1    # next seq_num to send for the first time
    timer_start = time.time()

    while base <= total:
        # Fill the window
        while next_seq <= total and next_seq < base + window_size:
            sock.sendto(packets[next_seq], dest)
            log("send", next_seq)
            next_seq += 1

        remaining = TIMEOUT - (time.time() - timer_start)
        if remaining <= 0:
            # Window did not advance within 500 ms: resend the whole window
            log("timeout, resend", base, "->", next_seq - 1)
            for seq in range(base, next_seq):
                sock.sendto(packets[seq], dest)
            timer_start = time.time()
            continue

        ack = recv_ack(sock, remaining)
        # Cumulative ACK = next seq_num the receiver expects.
        # Only an ACK that moves the window forward counts; old ones are ignored.
        if ack is not None and ack > base:
            base = min(ack, total + 1)
            timer_start = time.time()   # window moved -> reset timer
            log("window base ->", base)

    # ---- 3. END ----
    end_seq = total + 1
    end_pkt = make_packet(END, end_seq)
    sock.sendto(end_pkt, dest)
    deadline = time.time() + TIMEOUT    # exit after at most 500 ms
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        ack = recv_ack(sock, min(remaining, 0.1))
        if ack is not None and ack >= end_seq + 1:
            break                       # got the ACK of END
        if ack is None:
            sock.sendto(end_pkt, dest)  # END may have been lost, resend it

    sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()