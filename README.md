# Switch-implementation

* Forward with learning & VLAN:
    - forward with learning: as the switch learns the MAC addresses and uses
    a dictionary (MAC_table{}) to store them, later then checking if the destination
    is known to forward the frame to the correct port, or if not, flooding the frame
    to all ports except the one it came from. 
    - VLAN: the init function checks whether the port is access type or trunk
    and if it is access it removes the 802.1Q tag and then later on adds it back
    when forwarding the frame to a following trunk port. This ensures that the
    frame is forwarded correctly to all ports, adding the tag only when necessary.
    The vlan_id is read from the configuration file with the help of get_port_id
    function, so that the frames are frwarded only to ports with matching VLAN_ids
    (There is also the get_switch_priority used for the STP task).

* Task 3 - STP: 
    - The switch uses a STP instance to keep track of the network topology, as
    I have found it more interesting to work with this type of struct in which
    I put the variables I needed for the STP implementation. The main logic sits
    in the given pseudocode (that really helped in understanding the task better),
    which I have implemented in the stp function: each switch starts by "being" a
    root bridge, sending a BPDU to all trunk ports (which contains the root bridge id,
    path cost and its own bridge id). When such a frame is received, the switch
    updates its root bridge ID, path cost and sets the interface on which the BPDU was
    receied as the root port. If the switch is not the root bridge anymore, it forwards
    the BPDU on the other trunk ports. If the BPDU root bridge ID is the same as the
    switch's own bridge ID, the switch compares the path costs to see if it is in need
    of an update. The data is concatenated correctly following the Configuration BPDUs
    format, and later on sent with the help of the send_bdpu_every_sec function. The
    switch runs this algorithm only when the destination MAC address
    is the recquired one.

* I used the following struct:
stp_state = {
    "root_bridge_ID": 0, - the current root bridge ID
    "root_path_cost": 0, - the cost to reach the root bridge
    "own_bridge_ID": 0, - the switch's own bridge ID
    "root_port": None, - the port that leads to the root bridge
    "port_state": {}, - a dictionary with the state of each port: "BLOCKING"/"DESIGNATED"
    "hello_time": 2,
    "forward_delay": 15 - 
}

    
