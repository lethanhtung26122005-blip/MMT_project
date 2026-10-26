import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

START, END, DATA, ACK = 0, 1, 2, 3
HEADER_SIZE = 16


def build(header, payload):
    return header / payload if payload else header


def make_ack(seq_num):
    header = PacketHeader(type=ACK, seq_num=seq_num, length=0)
    header.checksum = compute_checksum(header)
    return bytes(header)


def parse_packet(raw):
    """Return (header, payload) if the checksum is valid, otherwise None."""
    if len(raw) < HEADER_SIZE:
        return None
    header = PacketHeader(raw[:HEADER_SIZE])
    payload = raw[HEADER_SIZE:HEADER_SIZE + header.length]
    received_checksum = header.checksum
    header.checksum = 0
    if compute_checksum(build(header, payload)) != received_checksum:
        return None
    return header, payload


def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    out = sys.stdout.buffer
    connected = False
    expected = 1    # next in-order seq_num we are waiting for (N)
    buffer = {}     # out-of-order packets: seq_num -> payload

    while True:
        raw, address = s.recvfrom(2048)
        parsed = parse_packet(raw)
        if parsed is None:
            continue                    # corrupted -> drop, no ACK
        header, payload = parsed

        if header.type == START:
            if not connected:           # ignore START in the middle of a connection
                connected = True
                expected = 1
                buffer.clear()
                s.sendto(make_ack(1), address)

        elif header.type == DATA and connected:
            seq = header.seq_num
            if seq >= expected + window_size:
                continue                # outside the window -> drop, no ACK
            if seq >= expected:
                buffer[seq] = payload   # buffer (also out-of-order packets)
                while expected in buffer:   # deliver everything now in order
                    out.write(buffer.pop(expected))
                    expected += 1
                out.flush()
            # Cumulative ACK = next expected seq_num.
            # Old duplicates (seq < expected) are not written again, but still ACKed.
            s.sendto(make_ack(expected), address)

        elif header.type == END and connected:
            if header.seq_num == expected:  # only finish when all data arrived
                s.sendto(make_ack(header.seq_num + 1), address)
                out.flush()
                break

    s.close()


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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()