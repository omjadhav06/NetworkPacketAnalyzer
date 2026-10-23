
import time
import traceback

from scapy.all import AsyncSniffer, conf, get_if_list

print("=" * 55)
print("NETWORK PACKET CAPTURE DIAGNOSTIC")
print("=" * 55)

print("\nAvailable interfaces:")
for index, interface in enumerate(get_if_list(), start=1):
    print(f"{index}. {interface}")

interface = input(
    "\nPaste the exact interface name from the list: "
).strip()

if interface not in get_if_list():
    print("\nERROR: Interface name does not match the list.")
    raise SystemExit(1)

captured = []

def handle_packet(packet):
    captured.append(packet)

    print(
        f"Packet #{len(captured)} | "
        f"Length: {len(packet)} bytes | "
        f"Summary: {packet.summary()}"
    )

sniffer = None

try:
    print("\nStarting capture...")
    print("Generate traffic by opening a website or running ping.")
    print("Capture duration: 15 seconds.\n")

    sniffer = AsyncSniffer(
        iface=interface,
        prn=handle_packet,
        store=False
    )

    sniffer.start()

    for second in range(15):
        time.sleep(1)

        if not sniffer.running:
            print("\nERROR: The capture thread stopped unexpectedly.")
            break

        print(
            f"\rElapsed: {second + 1}/15 seconds | "
            f"Packets: {len(captured)}",
            end="",
            flush=True
        )

    print()

except Exception:
    print("\nCAPTURE ERROR:")
    traceback.print_exc()

finally:
    if sniffer is not None:
        try:
            if sniffer.running:
                sniffer.stop(join=True)
        except Exception:
            traceback.print_exc()

print("\n" + "=" * 55)
print(f"TOTAL PACKETS CAPTURED: {len(captured)}")
print("=" * 55)

if captured:
    print("RESULT: Live packet capture works on this interface.")
else:
    print("RESULT: No packets captured. Check the interface and permissions.")
