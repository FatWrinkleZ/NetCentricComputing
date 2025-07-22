import sys
import struct
from socket import socket, AF_INET, SOCK_DGRAM

def create_query(id, domain_name):
    header = struct.pack(
        '!HHHHHH',
        id,
        0x0100,
        1,
        0,
        0,
        0
    )

    qname = b''
    labels = domain_name.split('.')
    for label in labels:
        qname += bytes([len(label)]) + label.encode('utf-8')
    qname += b'\x00'
    qtype = 1
    qclass = 1
    question = qname + struct.pack('!HH', qtype, qclass)

    return header + question

def parse_name(index, response):
    name = []
    visited = set()
    while True:
        if index >= len(response):
            break
        label_length = response[index]
        if label_length == 0:
            index += 1
            break
        elif label_length & 0xC0:
            if index + 1 >= len(response):
                break
            offset = struct.unpack('!H', response[index:index+2])[0] & 0x3FFF
            if offset in visited:
                break
            visited.add(offset)
            sub_name, _ = parse_name(offset, response)
            name.append(sub_name)
            index += 2
            break
        else:
            index += 1
            if index + label_length > len(response):
                break
            label = response[index:index + label_length].decode('utf-8', errors='ignore')
            name.append(label)
            index += label_length
            if index < len(response) and response[index] != 0:
                name.append('.')
    return ''.join(name), index

def parse_resource_record(index, response):
    name, index = parse_name(index, response)
    if index + 10 > len(response):
        return None, index
    type_code, class_code, ttl, rdlength = struct.unpack('!HHIH', response[index:index+10])
    index += 10
    rdata = None
    if type_code == 2:
        rdata, index = parse_name(index, response)
    elif type_code == 1:
        if rdlength == 4:
            rdata = '.'.join(str(b) for b in response[index:index+4])
            index += rdlength
    else:
        index += rdlength
    return (name, type_code, rdata), index

def parse_response(response, domain_name):
    index = 0
    if len(response) < 12:
        return None, None, None, None
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
    index = 12

    for _ in range(qdcount):
        _, index = parse_name(index, response)
        if index + 4 > len(response):
            return None, None, None, None
        index += 4

    answers = []
    authority = []
    additional = []
    
    for _ in range(ancount):
        rr, index = parse_resource_record(index, response)
        if rr:
            answers.append(rr)
    
    for _ in range(nscount):
        rr, index = parse_resource_record(index, response)
        if rr:
            authority.append(rr)
    
    for _ in range(arcount):
        rr, index = parse_resource_record(index, response)
        if rr:
            additional.append(rr)

    return answers, authority, additional, index

def print_response(answers, authority, additional):
    print(f"Reply received. Content overview:")
    print(f"{len(answers)} Answers.")
    print(f"{len(authority)} Intermediate Name Servers.")
    print(f"{len(additional)} Additional Information Records.")
    print()

    if answers:
        print("Answers section:")
        for name, type_code, rdata in answers:
            if type_code == 1:  # A record
                print(f"Name: {name} IP: {rdata}")
        print()

    if authority:
        print("Authority section:")
        for name, type_code, rdata in authority:
            if type_code == 2:
                print(f"Name: {name} Name Server: {rdata}")
        print()

    if additional:
        print("Additional Information Section:")
        for name, type_code, rdata in additional:
            if type_code == 1:
                print(f"Name: {name} IP: {rdata}")
        print()

def main():
    if len(sys.argv) != 3:
        print('Usage: python mydns.py domain-name root-dns-ip')
        sys.exit(1)
    
    domain_name = sys.argv[1]
    current_dns_ip = sys.argv[2]
    query_id = 1

    with socket(AF_INET, SOCK_DGRAM) as s:
        s.settimeout(5)
        while True:
            print(f"DNS server to query: {current_dns_ip}")
            query = create_query(query_id, domain_name)
            try:
                s.sendto(query, (current_dns_ip, 53))
                response, _ = s.recvfrom(2048)
            except Exception as e:
                print(f"Error querying {current_dns_ip}: {e}")
                sys.exit(1)

            answers, authority, additional, _ = parse_response(response, domain_name)
            if answers is None:
                print("Bruh, It didn werk.")
                sys.exit(1)

            print_response(answers, authority, additional)

            for name, type_code, rdata in answers:
                if type_code == 1 and name == domain_name:
                    return

            next_ns = None
            for _, type_code, rdata in authority:
                if type_code == 2:
                    next_ns = rdata
                    break
            
            if not next_ns:
                print("NO MORE SERVERS")
                sys.exit(1)

            next_ip = None
            for name, type_code, rdata in additional:
                if type_code == 1 and name == next_ns:
                    next_ip = rdata
                    break
            
            if not next_ip:
                print(f"NO IP FOR {next_ns}.")
                sys.exit(1)

            current_dns_ip = next_ip
            query_id += 1
            print()

if __name__ == '__main__':
    main()