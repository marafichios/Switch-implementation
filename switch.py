#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

MAC_table = {}
switch_priority = {}

stp_state = {
    "root_bridge_ID": 0,
    "root_path_cost": 0,
    "own_bridge_ID": 0,
    "root_port": None,
    "port_state": {},
    "hello_time": 2,
    "forward_delay": 15
}

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF
        ether_type = (data[16] << 8) + data[17]
    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec(stp_state, switch_id, interfaces):
    while True:
        if stp_state["root_bridge_ID"] == stp_state["own_bridge_ID"]:
            for port in interfaces:
                if get_port_id(switch_id, get_interface_name(port)) == 'T':
                    data = bpdu_frame(1, stp_state)
                    send_to_link(port, 52, data)
        time.sleep(1)

def bpdu_frame(age, stp_state):
    total_length = 38 # 38 bytes for the STP payload
    mac_address_str = '01:80:c2:00:00:00'
    
    destination_mac = bytes(int(x, 16) for x in mac_address_str.split(':'))
    switch_mac = get_switch_mac()
    length_bytes = total_length.to_bytes(2, 'big')
    
    frame_hdr = destination_mac + switch_mac + length_bytes
    llc_header = struct.pack('!3B', 0x42, 0x42, 0x03)
    
    stp_payload = (
        struct.pack('!H', 0x0000) +
        struct.pack('!B', 0x00) +
        struct.pack('!B', 0x00) +
        struct.pack('!B', 0x00) +
        stp_state["root_bridge_ID"].to_bytes(8, 'big') +
        stp_state["root_path_cost"].to_bytes(4, 'big') +
        stp_state["own_bridge_ID"].to_bytes(8, 'big') +
        struct.pack('!H', 0x8004) +
        age.to_bytes(2, 'big') +
        stp_state["hello_time"].to_bytes(2, 'big') +
        stp_state["forward_delay"].to_bytes(2, 'big')
    )
    
    return frame_hdr + llc_header + stp_payload

def get_port_id(switch_id, port):
    config_file = f'./configs/switch{switch_id}.cfg'

    # read the config file and get the VLAN ID for the port
    with open(config_file, 'r') as file:
        lines = file.readlines()[1:]
        vlan_match = [line.split()[1] for line in lines if line.split()[0] == port]

    return vlan_match[0] if vlan_match else ''

def get_switch_priority(switch_id):
    config_file = f'./configs/switch{switch_id}.cfg'

    # read the config file and get the switch priority
    with open(config_file, 'r') as file:
        lines = file.readlines()
        switch_priority[switch_id] = int(lines[0].split()[0])

def init_frame(data, length, vlan_id, interface, switch_id):
    # remove the VLAN for trunk ports
    if vlan_id == -1:
        vlan = get_port_id(switch_id, get_interface_name(interface))
    else:
        vlan = vlan_id
        length -= 4
        data = data[0:12] + data[16:]

    return vlan, data, length

def forward_frame(data, length, vlan_id, interface, switch_id, port):
    vlan, prepared_data, adjusted_length = init_frame(data, length, vlan_id, interface, switch_id)
    port_vlan_id = get_port_id(switch_id, get_interface_name(port))

    # if the port is not a trunk port, send the frame to the port
    if str(port_vlan_id) == str(vlan):
        send_to_link(port, adjusted_length, prepared_data)
    # if the port is a trunk port, add the VLAN tag and send the frame to the port
    elif port_vlan_id == 'T':
        tagged_frame = prepared_data[0:12] + create_vlan_tag(int(vlan)) + prepared_data[12:]
        send_to_link(port, adjusted_length + 4, tagged_frame)


def forward_with_learning(data, length, dest_mac, vlan_id, interfaces, interface, switch_id):
    if dest_mac != get_switch_mac():
            if dest_mac in MAC_table and stp_state["port_state"][MAC_table[dest_mac]] == "DESIGNATED":
                forward_frame(data, length, vlan_id, interface, switch_id, MAC_table[dest_mac])
            else:
                for port in interfaces:
                    if port != interface and stp_state["port_state"][port] == "DESIGNATED":
                        forward_frame(data, length, vlan_id, interface, switch_id, port)
    else:
        for port in interfaces:
            if port != interface and stp_state["port_state"][port] == "DESIGNATED":
                forward_frame(data, length, vlan_id, interface, switch_id, port)

def init_stp_state(stp_state, switch_id, interfaces):
    stp_state["own_bridge_ID"] = switch_priority[switch_id]
    stp_state["root_bridge_ID"] = stp_state["own_bridge_ID"]

    for i in interfaces:
        if get_port_id(switch_id, get_interface_name(i)) == 'T':
            stp_state["port_state"][i] = "BLOCKING"
        else:
            stp_state["port_state"][i] = "DESIGNATED"

    if stp_state["own_bridge_ID"] == stp_state["root_bridge_ID"]:
        for port in interfaces:
            stp_state["port_state"][port] = "DESIGNATED"

def stp(data, interface, stp_state, switch_id, interfaces):
    # extract the designated fields from the BPDU
    bpdu_root_bridge = int.from_bytes(data[22:30], byteorder='big')
    bpdu_path_cost = int.from_bytes(data[30:34], byteorder='big')
    bpdu_sender_bridge = int.from_bytes(data[34:42], byteorder='big')

    if bpdu_root_bridge < stp_state["root_bridge_ID"]:
        initial_root_bridge = stp_state["root_bridge_ID"]
        stp_state["root_bridge_ID"] = bpdu_root_bridge
        stp_state["root_path_cost"] = bpdu_path_cost + 10
        stp_state["root_port"] = interface

        if initial_root_bridge == switch_priority[switch_id]:
            for i in interfaces:
                if get_port_id(switch_id, get_interface_name(i)) == 'T' and i != interface:
                    stp_state["port_state"][i] = "BLOCKING"
        
        if stp_state["port_state"][interface] == "BLOCKING":
            stp_state["port_state"][interface] = "LISTENING"
        
        for i in interfaces:
            if get_port_id(switch_id, get_interface_name(i)) == 'T' and i != interface:
                data = bpdu_frame(1, stp_state)
                send_to_link(i, 50, data)

    elif bpdu_root_bridge == stp_state["root_bridge_ID"]:
        if interface == stp_state["root_port"] and bpdu_path_cost + 10 < stp_state["root_path_cost"]:
            stp_state["root_path_cost"] = bpdu_path_cost + 10
        
        elif interface != stp_state["root_port"]:
            if bpdu_path_cost > stp_state["root_path_cost"]:
                stp_state["port_state"][interface] = "DESIGNATED"

    elif bpdu_sender_bridge == stp_state["own_bridge_ID"]:
        stp_state["port_state"][interface] = "BLOCKING"
        
    if stp_state["own_bridge_ID"] == stp_state["root_bridge_ID"]:
        for i in interfaces:
            if get_port_id(switch_id, get_interface_name(i)) == 'T':
                stp_state["port_state"][i] = "DESIGNATED"

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    get_switch_priority(switch_id)

    # Create and start a new thread that deals with sending bpdu
    t = threading.Thread(target=send_bdpu_every_sec, args=(stp_state, switch_id, interfaces))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))
        
    init_stp_state(stp_state, switch_id, interfaces)

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        # TODO: Implement STP support
        if dest_mac == '01:80:c2:00:00:00':
            stp(data, interface, stp_state, switch_id, interfaces)
            continue
        
        if stp_state["port_state"][interface] == "BLOCKING":
            continue

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        MAC_table[src_mac] = interface
        forward_with_learning(data, length, dest_mac, vlan_id, interfaces, interface, switch_id)

if __name__ == "__main__":
    main()
