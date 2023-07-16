import scapy.all as scapy

# Open the pcapng file
try:
    pcapng = open("Wireshark Analyzer/SAMPLE.pcapng", "rb")
except FileNotFoundError:
    print("File not found.")
    exit(1)  # Exit the program if the file is not found

# Read the packets from the pcapng file
try:
    packets = scapy.rdpcap(pcapng)
except scapy.ScapyException:
    print("Error occurred while reading packets from the file.")
    pcapng.close()
    exit(1)  # Exit the program if an error occurs during packet reading

# Iterate over the packets
for packet in packets:
    try:
        # Check if the packet is a TCP packet
        if packet.haslayer(scapy.TCP):
            # Print the packet details
            print(packet)
    except Exception as e:
        print("Error occurred while processing a packet:", str(e))

# Close the pcapng file
pcapng.close()
