# author: Amiad korman & Ron Hodadedi

    from scapy.all import Ether, ARP, srp, sniff, conf
    import socket
    import os

    def get_mac(ip):
        """
        Returns the MAC address of `ip`, if it is unable to find it
        for some reason, throws `IndexError`
        """
        p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
        result = srp(p, timeout=3, verbose=False)[0]

        return result[0][1].hwsrc

    def process(packet):
    # if the packet is an ARP packet
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                # get the MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                # if they're different, definitely there is an attack
                if real_mac != response_mac:
                    print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
                    real_ip = get_ip(real_mac)
                    defeance(real_ip)
            except IndexError:
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass


    def get_ip(mac_address):

        # Send an ARP request to the device
        resp = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=mac), timeout=3, verbose=0)

        # Get the IP address from the response
        ip = resp[0][ARP].psrc

        return ip

    def defeance(ip_a):

        # Restart the network interface with the specified name
        os.system('ip link set eth0 down')
        os.system('ip link set eth0 up')
        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the IP address of the computer you want to block
        sock.bind(ip_a)

        # Listen for incoming connections on the socket
        sock.listen()

        # Accept any incoming connections and immediately close them
        while True:
            conn, addr = sock.accept()
            conn.close()

    







            
if __name__ == "__main__":
    import sys
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = conf.iface
    sniff(store=False, prn=process, iface=iface)