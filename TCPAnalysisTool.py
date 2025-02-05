import struct
import socket
import sys

def main():
    """
    Main function to parse a CAP file and output the formatted connections.
    """
    # Ensure a file path is provided via command-line arguments
    if len(sys.argv) != 2:
        print("Usage: python your_script.py <path_to_cap_file>")
        sys.exit(1)  

    # Get the file path from the command line
    file_path = sys.argv[1]

    # Parse the CAP file to extract connections
    TCP_connections = parse_cap_file(file_path)

    # Print all the information for the TCP connections
    print_all_info(TCP_connections)

    

def read_cap_header(file):
    """
    Read the global header from the CAP file
    
    Args:
        f: The CAP file
    
    Returns:
        Global header of the CAP file
    """
    
    # Read the first 24 bytes of the CAP file
    cap_file_global_header = file.read(24)
    
    # Return the global header of the CAP file
    return cap_file_global_header



def read_packet_header(f):
    """
    Read the packet header and return its details.
    
    Args:
        f: The file object of the CAP file.
    
    Returns:
        tuple:(timestamp_packet, included_len) 
        OR
        Returns None if the end of file
    """
    # Read Packet Header
    packet_header = f.read(16)
    
    # If the length of the packet header is less than 16 bytes the end of the file is reached
    if len(packet_header) < 16:
        return None
    
    # Unpack the packet header to extract the timestamp (seconds and microseconds) and lengths
    timestamp_sec, timestamp_microsec, included_len, original_len = struct.unpack('=IIII', packet_header)
    
    # Calculate the timestamp by adding the seconds and microseconds
    timestamp_packet = timestamp_sec + timestamp_microsec / 1_000_000
    
    # Return the timestamp and the included length of the packet
    return timestamp_packet, included_len



def parse_ip_and_protocol(packet_data):
    """
    Parse Ethernet and IP headers
    
    Args:
        packet_data: The raw packet data.
    
    Returns:
        tuple: (protocol, source_ip, destination_ip)
        OR
        tuple: (None, None, None) if the packet is not IPv4
    """
    # Extract the Ethernet protocol type
    eth_protocol = struct.unpack('!H', packet_data[12:14])[0]
    
    # Check if the Ethernet protocol type is IPv4 
    if eth_protocol != 0x0800:
        return None, None, None  # Not IPv4
    
    # Extract the IP header from the packet data
    ip_header = packet_data[14:34]
    
    # Unpack the IP header to extract the protocol and IP addresses
    ip_header_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = ip_header_data[6]
    source_ip = socket.inet_ntoa(ip_header_data[8])
    destination_ip = socket.inet_ntoa(ip_header_data[9])
    
    # Return the protocol, source IP address, and destination IP address
    return protocol, source_ip, destination_ip



def parse_tcp_header(packet_data):
    """
    Parse TCP header and return details.
    
    Args:
        packet_data: Raw packet data.
    
    Returns:
        tuple: (source_port, destination_port, sequence, ack_sequence, syn_flag, fin_flag, rst_flag, ack_flag, window_size)
    """
    # Extract the TCP header from the packet data (20 bytes after the IP header)
    tcp_header = packet_data[34:54]
    
    # Unpack the TCP header to extract the source port, destination port, sequence number,
    # acknowledgment number, and offset/reserved/flags
    source_port, destination_port, sequence, ack_sequence, offset_reserved_flags = struct.unpack('!HHLLH', tcp_header[:14])
    
    # Extract the flags from the offset/reserved/flags field
    flags = offset_reserved_flags & 0x3F
    syn_flag = (flags & 0x02) != 0
    fin_flag = (flags & 0x01) != 0
    rst_flag = (flags & 0x04) != 0
    ack_flag = (flags & 0x10) != 0
    
    # Extract the window size from the TCP header
    window_size = struct.unpack('!H', tcp_header[14:16])[0]
    
    # Return the extracted details as a tuple
    return source_port, destination_port, sequence, ack_sequence, syn_flag, fin_flag, rst_flag, ack_flag, window_size



def initialize_connection():
    """
    Initialize a dictionary to store connection details.
    
    Args: N/A

    Returns:
        dict: A dictionary with the keys:
            - 'start_time': The start time of the connection (initially None).
            - 'end_time': The end time of the connection (initially None).
            - 'packets_src_to_dst': The number of packets sent from source to destination.
            - 'packets_dst_to_src': The number of packets sent from destination to source.
            - 'bytes_src_to_dst': The number of bytes sent from source to destination.
            - 'bytes_dst_to_src': The number of bytes sent from destination to source.
            - 'window_sizes': A list to store window sizes.
            - 'rtt_times': A list to store round-trip times (RTT).
            - 'syn_count': The count of SYN packets.
            - 'fin_count': The count of FIN packets.
            - 'reset': A flag indicating if the connection was reset.
            - 'is_complete': A flag indicating if the connection is complete.
            - 'unacknowledged': A dictionary to store unacknowledged packets.
    """
    
    return {
        'start_time': None,
        'end_time': None,
        'packets_src_to_dst': 0,
        'packets_dst_to_src': 0,
        'bytes_src_to_dst': 0,
        'bytes_dst_to_src': 0,
        'window_sizes': [],
        'rtt_times': [],
        'syn_count': 0,
        'fin_count': 0,
        'reset': False,
        'is_complete': False,
        'unacknowledged': {}
    }

def parse_cap_file(file):
    """Parse the CAP file to gather TCP connection information."""
    # Initialize an empty dictionary to store connection details
    connections = {}

    # Open the CAP file in binary read mode
    with open(file, 'rb') as f:
        # Read the global header of the CAP file
        read_cap_header(f)
        packet_start_time = None

        # Loop to read each packet in the CAP file
        while True:
            # Read the packet header and get its details
            packet_details = read_packet_header(f)
            if packet_details is None:
                break  # End of file reached
            packet_timestamp, packet_included_length = packet_details
            # Read the packet data based on the included length
            packet_data = f.read(packet_included_length)

            # Set the start time for the first packet
            if packet_start_time is None:
                packet_start_time = packet_timestamp
            # Calculate the relative time of the packet
            relative_time = packet_timestamp - packet_start_time

            # Parse the IP and protocol from the packet data
            protocol, src_ip, dst_ip = parse_ip_and_protocol(packet_data)
            if protocol != 6:  # Not TCP
                continue

            # Parse the TCP header from the packet data
            src_port, dst_port, seq, ack_seq, syn_flag, fin_flag, rst_flag, ack_flag, window_size = parse_tcp_header(packet_data)
            # Normalize the connection direction for consistency
            connection_key, direction = normalize_connection(src_ip, src_port, dst_ip, dst_port)

            # Initialize a new connection if it doesn't exist in the dictionary
            if connection_key not in connections:
                connections[connection_key] = initialize_connection()

            # Update the connection details based on the packet information
            update_connection(connections[connection_key], direction, relative_time, packet_included_length, seq, ack_seq, syn_flag, fin_flag, rst_flag, ack_flag, window_size)

    # Return the dictionary containing all connection details
    return connections

def normalize_connection(src_ip, src_port, dst_ip, dst_port):
    """
    Normalize connection direction to ensure consistency in dictionary keys.
    
    Args:
        src_ip: Source IP address.
        src_port: Source port number.
        dst_ip: Destination IP address.
        dst_port: Destination port number.
    
    Returns:
        tuple: A tuple containing the normalized connection key and the direction.
               The connection key is a tuple of (src_ip, src_port, dst_ip, dst_port) or
               (dst_ip, dst_port, src_ip, src_port) based on the comparison.
               The direction is a string 'src_to_dst' or 'dst_to_src' indicating the direction.
    """
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (dst_ip, dst_port, src_ip, src_port), 'dst_to_src'
    else:
        return (src_ip, src_port, dst_ip, dst_port), 'src_to_dst'
    
    

def update_connection(conn, direction, relative_time, included_length, sequence, ack_sequence, syn_flag, fin_flag, rst_flag, ack_flag, window_size):
    """
    Update connection information based on packet details.
    
    Args:
        conn: The connection dictionary to update
        direction: The direction of the packet 
        relative_time: The relative time of the packet
        included_length: The included length of the packet
        sequence: The sequence number of the packet
        ack_sequence: The acknowledgment number of the packet
        syn_flag: The SYN flag of the packet
        fin_flag: The FIN flag of the packet
        rst_flag: The RST flag of the packet
        ack_flag: The ACK flag of the packet
        window_size: The window size of the packet
    """
    # If the packet has the SYN flag increment the SYN count and set the start time
    if syn_flag:
        conn['syn_count'] += 1
        if conn['start_time'] is None:
            conn['start_time'] = relative_time
    
    # If the packet has the FIN flag increment the FIN count and set the end time
    if fin_flag:
        conn['fin_count'] += 1
        conn['end_time'] = relative_time
    
    # If the packet has the RST flag mark the connection as reset
    if rst_flag:
        conn['reset'] = True

    # Update the connection information based on the direction of the packet
    if direction == 'src_to_dst':
        conn['packets_src_to_dst'] += 1
        conn['bytes_src_to_dst'] += (included_length - 54)
        if not ack_flag:
            conn['unacknowledged'][sequence] = relative_time
    else:
        conn['packets_dst_to_src'] += 1
        conn['bytes_dst_to_src'] += (included_length - 54)
        if ack_flag:
            calculate_rtt(conn, ack_sequence, relative_time)

    # Append the window size to the list of window sizes
    conn['window_sizes'].append(window_size)
    
    # Mark the connection as complete if it has at least one SYN and one FIN packet
    conn['is_complete'] = conn['syn_count'] >= 1 and conn['fin_count'] >= 1
    
    

def calculate_rtt(conn, ack_sequence, relative_time):
    """
    Calculate RTT based on ACK and previously unacknowledged packets.
    
    Args:
        conn: Connection dictionary
        ack_sequence: Ack number of the packet.
        relative_time: Relative time of the packet
        
    Return: N/A
    """
    # Iterate over the unacknowledged packets to calculate RTT
    for unack_seq, send_time in list(conn['unacknowledged'].items()):
        # Check if the acknowledgment number is greater than or equal to the unacknowledged sequence number
        if ack_sequence >= unack_seq:
            # Calculate the RTT by subtracting the send time from the relative time
            rtt = relative_time - send_time
            # Append the calculated RTT to the list of RTT times
            conn['rtt_times'].append(rtt)
            # Remove the acknowledged packet from the unacknowledged dictionary
            del conn['unacknowledged'][unack_seq]
            # Break the loop after processing the first matching unacknowledged packet
            break


def calculate_connection_info(connections):
    """
    Calculate Info for TCP connections.
    
    Args:
        connections: A dictionary containing connection details.
    
    Return:
        dict: A dictionary with all necessary info.
    """
    # Initialize variables to store total duration, counts, and lists for info
    total_duration, complete_connections = 0, 0
    reset_connections, open_connections = 0, 0
    durations, packet_counts, window_sizes, rtt_times = [], [], [], []

    # Iterate over each connection in the connections dictionary
    for conn in connections.values():
        # Check if the connection was reset and increment the reset count
        if conn['reset']:
            reset_connections += 1

        # Check if the connection is complete
        if conn['is_complete']:
            # Increment the complete connections count
            complete_connections += 1
            # Add the connection duration to the total duration
            total_duration += (conn['end_time'] - conn['start_time'])
            # Append the connection duration to the durations list
            durations.append(conn['end_time'] - conn['start_time'])
            # Append the total packet count to the packet counts list
            packet_counts.append(conn['packets_src_to_dst'] + conn['packets_dst_to_src'])
            # Extend the window sizes list with the connection's window sizes
            window_sizes.extend(conn['window_sizes'])
        else:
            # Increment the open connections count if the connection is not complete
            open_connections += 1

        # Extend the RTT times list with the connection's RTT times
        rtt_times.extend(conn['rtt_times'])

    # Summarize and return the calculated info
    return all_info(total_duration, complete_connections, reset_connections, open_connections, durations, packet_counts, window_sizes, rtt_times)


def all_info(total_duration, complete_connections, reset_connections, open_connections, durations, packet_counts, window_sizes, rtt_times):
    """
    puts all info into a dictionary
    
    Args:
        total_duration: The total duration of all complete connections.
        complete_connections: The number of complete connections.
        reset_connections: The number of reset connections.
        open_connections: The number of open connections.
        durations: A list of durations for complete connections.
        packet_counts: A list of packet counts for complete connections.
        window_sizes: A list of window sizes for all connections.
        rtt_times: A list of RTT times for all connections.
    
    Return:
        dict: A dictionary containing all info.
    """
    
    total_connections = complete_connections + reset_connections + open_connections

    # Duration information
    min_duration = min(durations, default=0)
    max_duration = max(durations, default=0)
    
    if complete_connections > 0:
        mean_duration = total_duration / complete_connections
    else:
        mean_duration = 0

    # RTT information
    min_rtt = min(rtt_times, default=0)
    max_rtt = max(rtt_times, default=0)
    
    if rtt_times:
        mean_rtt = sum(rtt_times) / len(rtt_times)
    else: 
        mean_rtt = 0
        

    # Packet information
    min_packets = min(packet_counts, default=0)
    max_packets = max(packet_counts, default=0)
    
    if packet_counts:
        mean_packets = sum(packet_counts) / len(packet_counts)
    else:
        mean_packets = 0
    

    # Window size information
    min_window_size = min(window_sizes, default=0)
    max_window_size = max(window_sizes, default=0)
    
    if window_sizes:
        mean_window_size = sum(window_sizes) / len(window_sizes)
    else:
        mean_window_size = 0
    
    
    return {
        'total_connections': total_connections,
        'complete_connections': complete_connections,
        'reset_connections': reset_connections,
        'open_connections': open_connections,
        'min_duration': min_duration,
        'mean_duration': mean_duration,
        'max_duration': max_duration,
        'min_rtt': min_rtt,
        'mean_rtt': mean_rtt,
        'max_rtt': max_rtt,
        'min_packets': min_packets,
        'mean_packets': mean_packets,
        'max_packets': max_packets,
        'min_window_size': min_window_size,
        'mean_window_size': mean_window_size,
        'max_window_size': max_window_size,
    }
    
    
def print_all_info(connections):
    """
    Print the TCP connection information

    Args:
        connections (dict): A dictionary containing connection details
        
    Return: N/A
    """
    # Calculate info for the connections
    stats = calculate_connection_info(connections)
    
    # Print Total Connections
    print("A) Total number of connections:", stats['total_connections'])
    print("________________________________________________")
    
    # Print Connection Details
    print("\nB) Connection's details\n")
   
    items = list(connections.items())

    for i in range(len(items)):
        conn, details = items[i]
        
        src_ip, src_port, dst_ip, dst_port = conn
        print(f"Connection {i}:")
        print(f"Source Address: {src_ip}")
        print(f"Destination Address: {dst_ip}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        
        # Format the status based on SYN and FIN counts
        status = f"S{details['syn_count']}F{details['fin_count']}"
        print(f"Status: {status}")
        
        # Calculate and Print all times
        start_time = round(details['start_time'], 6) if details['start_time'] else 0.0
        end_time = round(details['end_time'], 6) if details['end_time'] else start_time
        duration = round(end_time - start_time, 6)
        print(f"Start time: {start_time} seconds")
        print(f"End Time: {end_time} seconds")
        print(f"Duration: {duration} seconds")
        
        # Print Packet and Byte Info
        packets_src_to_dst = details['packets_src_to_dst']
        packets_dst_to_src = details['packets_dst_to_src']
        bytes_src_to_dst = details['bytes_src_to_dst']
        bytes_dst_to_src = details['bytes_dst_to_src']
        print(f"Number of packets sent from Source to Destination: {packets_src_to_dst}")
        print(f"Number of packets sent from Destination to Source: {packets_dst_to_src}")
        print(f"Total number of packets: {packets_src_to_dst + packets_dst_to_src}")
        print(f"Number of data bytes sent from Source to Destination: {bytes_src_to_dst}")
        print(f"Number of data bytes sent from Destination to Source: {bytes_dst_to_src}")
        print(f"Total number of data bytes: {bytes_src_to_dst + bytes_dst_to_src}")
        print("END\n++++++++++++++++++++++++++++++++")

    # Print Part C
    print("________________________________________________")
    print("\nC) General\n")
    print("Total number of complete TCP connections:", stats['complete_connections'])
    print("Number of reset TCP connections:", stats['reset_connections'])
    print("Number of TCP connections that were still open when the trace capture ended:", stats['open_connections'])
    print("________________________________________________")
    
    # Print Part D
    print("\nD) Complete TCP connections\n")
    print(f"Minimum time duration: {stats['min_duration']} seconds")
    print(f"Mean time duration: {stats['mean_duration']} seconds")
    print(f"Maximum time duration: {stats['max_duration']} seconds")
    print(f"\nMinimum RTT value: {stats['min_rtt']}")
    print(f"Mean RTT value: {stats['mean_rtt']}")
    print(f"Maximum RTT value: {stats['max_rtt']}")
    print(f"\nMinimum number of packets including both send/received: {stats['min_packets']}")
    print(f"Mean number of packets including both send/received: {stats['mean_packets']}")
    print(f"Maximum number of packets including both send/received: {stats['max_packets']}")
    print(f"\nMinimum receive window size including both send/received: {stats['min_window_size']} bytes")
    print(f"Mean receive window size including both send/received: {stats['mean_window_size']} bytes")
    print(f"Maximum receive window size including both send/received: {stats['max_window_size']} bytes")

if __name__ == "__main__":
    main()
