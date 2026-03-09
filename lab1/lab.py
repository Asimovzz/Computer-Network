from scapy.all import *


################################################################################
# Part 1. sniffing and Ethernet parsing 
################################################################################

Trace1 = "http.pcap"


from threading import Thread
from time import sleep
import requests


def MySniff():
    print("sniffing start")
    #################################
    ###### start of your code #######
    #################################
    packets = sniff(timeout = 5)
    wrpcap(Trace1, packets)
    #################################
    ###### end of your code #########
    #################################
    print("sniffing stop")

    
def MyHttp():
    print("http start")
    x = requests.get('http://gaia.cs.umass.edu/wireshark-labs/HTTP-ethereal-lab-file3.html')
    print(x.status_code)
    sleep(1)
    print("http stop")


def Q1():
    t1 = Thread(target=MySniff)
    t2 = Thread(target=MyHttp)
    t1.start()
    sleep(1)
    t2.start()
    t2.join()
    t1.join()
    return "done"


def Q2():
    src_mac= ""
    dst_mac = ""
    #################################
    ###### start of your code #######
    #################################
    pkts = rdpcap(Trace1)
    for p in pkts:
        if TCP in p and p[TCP].dport == 80:
            src_mac = p[Ether].src
            dst_mac = p[Ether].dst
            break
    #################################
    ###### end of your code #########
    #################################
    return src_mac, dst_mac
    


def Q3():    
    theType = 0
    theProto = 0
    theTime = 0 
    #################################
    ###### start of your code #######
    #################################
    pkts = rdpcap(Trace1)
    req_pkt = None
    
    for p in pkts:
        if TCP in p and p[TCP].dport == 80:
            req_pkt = p
            break
        
    if req_pkt:
        for p in pkts:
            if TCP in p and IP in p:
                if req_pkt[IP].src == p[IP].dst and req_pkt[IP].dst == p[IP].src:
                    if req_pkt[TCP].dport == p[TCP].sport and req_pkt[TCP].sport == p[TCP].dport:
                        if "A" in str(p[TCP].flags):
                            theType = p[Ether].type
                            theProto = p[IP].proto
                            theTime = p.time
                            break
        
    #################################
    ###### end of your code #########
    #################################
    return theType, theProto, theTime
            


################################################################################
# Part 2. Trace analysis 
################################################################################

Trace2='univ.pcap'

def Q4():
    theLength = 0
    #################################
    ###### start of your code #######
    #################################
    packets = rdpcap(Trace2)
    theLength = len(packets)
    #################################
    ###### end of your code #########
    #################################
    return theLength

def Q5():
    num_tcp = 0
    num_udp = 0
    num_ip = 0
    #################################
    ###### start of your code #######
    #################################
    pkts = rdpcap(Trace2)
    for p in pkts:
        if IP in p:
            num_ip += 1
        if TCP in p:
            num_tcp += 1
        if UDP in p:
            num_udp += 1
    #################################
    ###### end of your code #########
    #################################
    return num_ip, num_tcp, num_udp

def Q6():
    flows = set()
    #################################
    ###### start of your code #######
    #################################
    pkts = rdpcap(Trace2)
    for p in pkts:
        if IP in p and TCP in p:
            flow = frozenset([ (p[IP].src, p[TCP].sport), (p[IP].dst, p[TCP].dport) ])
            flows.add(flow)
    #################################
    ###### end of your code #########
    #################################
    return len(flows)

def Q7():
    min_length = 0
    max_length = 0
    median_length = 0
    #################################
    ###### start of your code #######
    #################################
    pkts = rdpcap(Trace2)
    lengths = []
    
    for p in pkts:
        if IP in p:
            lengths.append(p[IP].len + 18)
        
    if lengths:
        lengths.sort()
        
        min_length = lengths[0]
        max_length = lengths[-1]
        
        n = len(lengths)
        if(n % 2 == 0):
            median_length = (lengths[n // 2 - 1] + lengths[n // 2]) / 2.0
        else:
            median_length = lengths[n // 2]
    #################################
    ###### end of your code #########
    #################################
    return min_length, median_length, max_length

