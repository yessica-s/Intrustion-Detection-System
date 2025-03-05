import sys
from scapy.all import rdpcap, TCP, UDP, ICMP, IP, raw
from scapy.packet import Raw
import time
from datetime import datetime

packet_timestamps = [] # store TCP packet timestamps
tcp_packets = 0 # store recorded TCP packets

def parse_rules_file(file_path):
    rules = []
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("#") or not line.strip():
                continue
            rule = line.strip().rstrip(');')  # Remove ');'
            rules.append(rule)
    return rules

def match_flags(flags, packet_flags):
    # the below flags and corresponding values were found from https://www.noction.com/blog/tcp-flags
    fin = 0b00000001
    neg_fin = 0b11111110
    syn = 0b00000010
    neg_syn = 0b11111101
    rst = 0b00000100
    neg_rst = 0b11111011
    ack = 0b00010000
    neg_ack = 0b11101111

    flag = flags[0] # ignore any trailing +

    # for flag in flags: # loop through flags required by rule
    if flag == 'F': # fin flag required
        if not (fin & packet_flags): # if that flag is not set in the packet
            return False
        if len(flags) == 1: # if non-wildcard option make sure no other flags are set
            temp = neg_fin & packet_flags
            if temp > 0: # some other flag was set
                return False
    elif flag == 'A': 
        if not (ack & packet_flags): # if that flag is not set in the packet
            return False
        if len(flags) == 1: # if non-wildcard option make sure no other flags are set
            temp = neg_ack & packet_flags
            if temp > 0: # some other flag was set
                return False
    elif flag == 'S': 
        if not (syn & packet_flags): # if that flag is not set in the packet
            return False
        if len(flags) == 1: # if non-wildcard option make sure no other flags are set
            temp = neg_syn & packet_flags
            if temp > 0: # some other flag was set
                return False
    elif flag == 'R': 
        if not (rst & packet_flags): # if that flag is not set in the packet
            return False
        if len(flags) == 1: # if non-wildcard option make sure no other flags are set
            temp = neg_rst & packet_flags
            if temp > 0: # some other flag was set
                return False
    return True

def extract_tcp_timestamp(packet):
    if TCP in packet and packet[TCP].options:
        for option in packet[TCP].options:
            if option[0] == 'Timestamp': 
                return option[1][0]  # Returns the timestamp value
    return None

def check_detection_filter(packet, count, seconds):
    # using packet timestamp method
    packet_timestamps.append(packet.time)

    # Method will remove any timestamps older than two seconds from most recent packet
    found = True
    while found == True:
        for ts in packet_timestamps:
            if packet_timestamps[len(packet_timestamps) - 1] - packet_timestamps[0] > int(seconds):
                found = True
                packet_timestamps.pop(0)
            found = False

    if len(packet_timestamps) > int(count): # if number of packets within 2 seconds of previous packet exceed count:
        return True
    return False

def match_packet(packet, rule):
    src_ip, src_port, dst_ip, dst_port, content, flags, count, seconds = parse_rule(rule)

    if IP not in packet:
        return False
    # check IP addresses match
    if src_ip != 'any' and packet[IP].src != src_ip:
            return False
    if dst_ip != 'any' and packet[IP].dst != dst_ip:
            return False

    # if 'tcp' in rule: # check TCP packets
    if TCP in packet and ('tcp' in rule or 'ip' in rule):
        if TCP not in packet or IP not in packet or ICMP in packet or UDP in packet:  # Ensure packet contains both TCP and IP
            return False     
        if not check_port_and_content(packet, TCP, src_port, dst_port, content):
            return False
        if len(flags) > 0: # If there are flags present in the rules          
            packet_flags = packet[TCP].flags # Get flags in packet
            if not match_flags(flags, packet_flags): # ensure all required flags are present
                return False
        if not (count == None or seconds == None):
            if not check_detection_filter(packet, count, seconds): # Check TCP flooding
                return False     
        return True
    if ICMP in packet and ('icmp' in rule or 'ip' in rule):
        if ICMP not in packet or IP not in packet or TCP in packet or UDP in packet:  # Ensure packet contains both ICMP and IP
            return False
        if not check_port_and_content(packet, ICMP, src_port, dst_port, content):
            return False
        if not (count == None or seconds == None):
            if not check_detection_filter(packet, count, seconds): # Check TCP flooding
                return False  
        return True
    if UDP in packet and ('udp' in rule or 'ip' in rule):
        if UDP not in packet or IP not in packet or TCP in packet or ICMP in packet: 
            return False
        if not check_port_and_content(packet, UDP, src_port, dst_port, content):
            return False
        if not (count == None or seconds == None):
            if not check_detection_filter(packet, count, seconds): # Check TCP flooding
                return False  
        return True
    return False # unknown protocol

def check_port_and_content(packet, protocol, src_port, dst_port, content):
    if src_port != 'any' and packet[protocol].sport != int(src_port):
        return False
    elif dst_port != 'any' and packet[protocol].dport != int(dst_port):
        return False
    elif content is not None and Raw in packet: # if there is a payload, decode it and check it
        payload = packet[Raw].load.decode(errors='ignore')
        if content not in payload:
            return False
    return True

# Parse source and destination IPs and Ports + content if present
def parse_rule(rule):
    rule = rule.rstrip(');')
    
    # Split the rule on spaces
    parts = rule.split()

    # Extract protocol, source IP, source port, destination IP, and destination port
    protocol = parts[1]
    src_ip = parts[2]
    src_port = parts[3]
    dst_ip = parts[5]
    dst_port = parts[6]

    content = None
    if 'content' in rule:
        content_start = rule.find('content:') + len('content:')
        if rule[content_start] == ' ': # if space present after ':'
            content_start += 1 # increment start to ignore space
        content_start = rule.find('"', content_start) + 1
        content_end = rule.find('"', content_start) 
        content = rule[content_start:content_end] # store content

    # Parse flags
    flags = []
    if 'flags' in rule:
        flag_start = rule.find('flags:') + len('flags:')
        if rule[flag_start] == ' ':  # if space present after ':'
            flag_start += 1
        flag_end = rule.find(';', flag_start)
        if flag_end == -1: # if ';' not found since end of rule set end of flags to end of rule
            flag_end = len(rule)
        flags_stripped = rule[flag_start:flag_end].strip() # separate the flags
        flags = flags_stripped

    # Parse count, seconds
    count = None
    seconds = None
    if 'detection_filter' in rule:
        count_start = rule.find('count ') + len('count ')
        count_end = rule.find(',', count_start)
        count = rule[count_start:count_end]

        seconds_start = rule.find('seconds ') + len('seconds ')
        seconds_end = rule.find(';', seconds_start)
        if seconds_end == -1: # not found since end of rule set
            seconds_end = len(rule)
        seconds = rule[seconds_start:seconds_end]

    return src_ip, src_port, dst_ip, dst_port, content, flags, count, seconds

def log_alert(message, file):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    file.write(f"{timestamp} - Alert: {message}\n")

def main():

    pcap_file = sys.argv[1]
    rules_file = sys.argv[2]

    rules = parse_rules_file(rules_file)
    packets = rdpcap(pcap_file)

    # Open the log file in write mode initially to clear its content
    with open('IDS_log.txt', 'w') as file:
        for packet in packets:
            for rule in rules:
                if match_packet(packet, rule):
                    msg_match = rule.find('msg:') # find where message starts
                    if msg_match != -1:
                        msg_start = rule.find('"', msg_match) + 1 # remove quotation marks
                        msg_end = rule.find('"', msg_start)
                        message = rule[msg_start:msg_end]
                        log_alert(message, file) # add message string to log file

if __name__ == "__main__":
    main()