
from scapy.all import conf, get_if_list

print("Scapy capture socket:", conf.L2listen)
print("\nAvailable network interfaces:")

interfaces = get_if_list()

for index, interface in enumerate(interfaces, start=1):
    print(f"{index}. {interface}")

if interfaces:
    print(f"\nFound {len(interfaces)} interfaces.")
else:
    print("\nNo interfaces detected. Check Npcap installation.")

