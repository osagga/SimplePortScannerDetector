from dpkt.pcap import Reader
from dpkt.tcp import TCP, TH_SYN, TH_ACK
from dpkt.ethernet import Ethernet
from dpkt.dpkt import NeedData
from socket import inet_ntoa as ntoa
from sys import argv

def parsePackets(filename, scaler):
    '''Given a pcap filename, this function will parse the packets and return the set of IPs that may have attemped to preform port scanning.'''
	
    try:
        filehandler = open(filename, 'rb')
    except OSError:
        print "Can't open file:", filename
        return

    pcapData = Reader(filehandler)

    # Two Dictanories to count
    SYN_Count = dict()
    SYNACK_Count = dict()

    for ts, packet in pcapData:

        # Test if the packet is not dameged.
        try:
            eth = Ethernet(packet)
        except NeedData:
            continue

        # Test if the packet is IPv4
        if eth.type!=2048:
            continue

        ip = eth.data

        # Test if the packet has TCP layer
        if ip.p!=6:
            continue

        src = ntoa(ip.src)
        dst = ntoa(ip.dst)

        tcp = ip.data

        syn_flag = ( tcp.flags & TH_SYN ) != 0
        ack_flag = ( tcp.flags & TH_ACK ) != 0

        if syn_flag and not ack_flag:
            # To check if the packet is only SYN
            if src in SYNACK_Count:
                SYN_Count[src] += 1
            else:
                SYN_Count[src] = 1

            if not (src in SYNACK_Count):
                SYNACK_Count[src] = 0

        elif syn_flag and ack_flag:
            # To check if the packet is at least SYN and ACK
            if dst in SYNACK_Count:
                SYNACK_Count[dst] += 1
            else:
                SYNACK_Count[dst] = 1

            if not (dst in SYN_Count):
                SYN_Count[dst] = 0

    setIP = set()
    for key in SYN_Count:
        c_syn = SYN_Count[key]
        c_synAck = SYNACK_Count[key]
        if c_syn > (scaler * c_synAck):
            # If the number of SYN requests is at least more than 'scaler' times the number of SYN,ACK responds
            setIP.add(key)
    return setIP

def main():
	try:
		scaler = int(argv[1])
		pcapFilename =  argv[2]
	except IndexError:
		print "Please make sure to pass a scaler value and capture file as arguments."
		return
	retSet = parsePackets(pcapFilename, scaler)
	for IP in retSet:
		print IP
	return

if __name__ == "__main__":
    main()
