from scapy.all import rdpcap, TCP, Raw, IP
import urllib.parse
import re

# Regex to capture position and ASCII value from the SQL injection enumeration
sqli_pattern = re.compile(
    r"ASCII\s*\(\s*SUBSTR\s*\(\s*\(\s*SELECT\s+TABLE_NAME.+?\)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*=\s*(\d+)",
    re.IGNORECASE
)

def extract_sqli_char_and_pos(uri):
    decoded_uri = urllib.parse.unquote_plus(uri)
    match = sqli_pattern.search(decoded_uri)
    if match:
        pos = int(match.group(1))
        ascii_val = int(match.group(2))
        try:
            char = chr(ascii_val)
            return pos, char
        except:
            return pos, None
    return None, None

def update_guess_string(current_string, pos, char):
    idx = pos - 1
    if idx < 0:
        return current_string
    if len(current_string) <= idx:
        current_string.extend([' '] * (idx - len(current_string) + 1))
    current_string[idx] = char
    return current_string

def extract_http_get_requests(pcap_file):
    packets = rdpcap(pcap_file)
    tcp_streams = {}
    combined_guess = []  # single global array for all streams

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            tcp = pkt[TCP]
            raw_data = pkt[Raw].load
            stream_id = (pkt[IP].src, tcp.sport, pkt[IP].dst, tcp.dport)

            if stream_id not in tcp_streams:
                tcp_streams[stream_id] = b""
            tcp_streams[stream_id] += raw_data

    for stream_id, data in tcp_streams.items():
        try:
            http_text = data.decode(errors='ignore')
            requests = re.split(r'(?=GET\s)', http_text)

            for req in requests:
                if req.startswith("GET "):
                    m = re.search(r"GET\s+(\S+)\s+HTTP/", req)
                    if m:
                        uri = m.group(1)
                        pos, char = extract_sqli_char_and_pos(uri)
                        if pos and char:
                            combined_guess = update_guess_string(combined_guess, pos, char)
                            current_guess = ''.join(combined_guess)
                            print(f"Current combined guess: '{current_guess}'")
        except Exception:
            continue

if __name__ == "__main__":
    pcap_path = "/content/Someone stole my table.pcap"  # Replace with your PCAP file path
    extract_http_get_requests(pcap_path)
