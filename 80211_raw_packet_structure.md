# 802.11 Raw Packet Structure Guide

## Frame Control Field Breakdown (2 bytes)

The Frame Control field is crucial for defining packet behavior. Here's the bit-by-bit breakdown:

```
Byte 1 (Protocol Version + Type + Subtype):
+---+---+---+---+---+---+---+---+
| B0| B1| B2| B3| B4| B5| B6| B7|
+---+---+---+---+---+---+---+---+
|Version |  Type   |   Subtype  |
|  (2)   |   (2)  |     (4)    |

Byte 2 (Flags):
+---+---+---+---+---+---+---+---+
| B0| B1| B2| B3| B4| B5| B6| B7|
+---+---+---+---+---+---+---+---+
|ToDS|FrDS|MF |Rtry|Pwr|MD |Pro|Ord|
```

### Frame Control Values

#### Type and Subtype Combinations (First Byte)
```
Management Frames (Type 00):
- 0x00: Association Request
- 0x10: Association Response
- 0x20: Reassociation Request
- 0x30: Reassociation Response
- 0x40: Probe Request
- 0x50: Probe Response
- 0x80: Beacon
- 0xB0: Authentication
- 0xC0: Deauthentication
- 0xA0: Disassociation

Control Frames (Type 01):
- 0x84: Block Ack Request
- 0x94: Block Ack
- 0xB4: RTS
- 0xC4: CTS
- 0xD4: ACK

Data Frames (Type 10):
- 0x08: Data
- 0x18: QoS Data
```

## General Packet Structure

An 802.11 packet consists of the following components:

1. **Frame Control (2 bytes)**: Indicates the type and subtype of the frame, as well as control flags.
2. **Duration/ID (2 bytes)**: Specifies the duration of the frame or an identifier.
3. **Addresses (6 bytes each)**:
   - Address 1: Destination MAC address
   - Address 2: Source MAC address
   - Address 3: BSSID (Basic Service Set Identifier)
4. **Sequence Control (2 bytes)**: Contains the sequence number and fragment number.
5. **Frame Body (variable length)**: Contains the payload or data of the frame.
6. **Frame Check Sequence (4 bytes)**: Used for error detection.

## Common Frame Structures

### 1. Authentication Frame (Detailed)

```
[RadioTap Header] (Variable length)
+------------------+----------------+----------------------+
| Field            | Size (bytes)   | Description         |
+------------------+----------------+----------------------+
| Header revision  | 1             | Usually 0x00         |
| Header pad       | 1             | Usually 0x00         |
| Header length    | 2             | Length of header     |
| Present flags    | 4             | Bit field of flags   |
+------------------+----------------+----------------------+

[802.11 Header]
+------------------+----------------+--------------------------------+
| Field            | Size (bytes)   | Value (Hex) + Description     |
+------------------+----------------+--------------------------------+
| Frame Control    | 2             | B0 00 (Authentication frame)   |
| Duration         | 2             | 00 00 (No duration set)        |
| Address 1        | 6             | Target MAC address             |
| Address 2        | 6             | Source MAC address             |
| Address 3        | 6             | BSSID                          |
| Sequence Control | 2             | xx xx (Sequence number)        |
+------------------+----------------+--------------------------------+

[Authentication Body]
+----------------------+----------------+--------------------------------+
| Field                | Size (bytes)   | Value (Hex) + Description     |
+----------------------+----------------+--------------------------------+
| Auth Algorithm       | 2             | 00 00 (Open System)           |
| Auth Sequence        | 2             | 01 00 (First frame)           |
| Status Code          | 2             | 00 00 (Successful)            |
+----------------------+----------------+--------------------------------+

### 2. Deauthentication Frame

| Field               | Bytes | Value (Hex) | Description                              |
|---------------------|-------|-------------|------------------------------------------|
| Frame Control       | 2     | `C0 00`     | Deauthentication frame                  |
| Duration/ID         | 2     | `00 00`     | Typically 0                              |
| Address 1 (Dest)    | 6     | `FF FF FF FF FF FF` | Broadcast                               |
| Address 2 (Source)  | 6     | `AA BB CC DD EE FF` | Source MAC                              |
| Address 3 (BSSID)   | 6     | `AA BB CC DD EE FF` | BSSID                                   |
| Sequence Control    | 2     | `00 00`     | Sequence number                          |
| Frame Body          | 2     | `07 00`     | Reason Code (7: Class 3 frame received)  |

### 3. Beacon Frame

| Field               | Bytes | Value (Hex) | Description                              |
|---------------------|-------|-------------|------------------------------------------|
| Frame Control       | 2     | `80 00`     | Beacon frame                             |
| Duration/ID         | 2     | `00 00`     | Typically 0                              |
| Address 1 (Dest)    | 6     | `FF FF FF FF FF FF` | Broadcast                               |
| Address 2 (Source)  | 6     | `AA BB CC DD EE FF` | Source MAC                              |
| Address 3 (BSSID)   | 6     | `AA BB CC DD EE FF` | BSSID                                   |
| Sequence Control    | 2     | `00 00`     | Sequence number                          |
| Frame Body          | Variable | SSID, supported rates, etc.              |

## Creating Custom Packets

To create your own raw packets, follow these steps:

1. **Define the Frame Control Field**:
   - Determine the type and subtype of the frame (e.g., Beacon, Deauthentication).
   - Set the appropriate flags (e.g., ToDS, FromDS).

2. **Set the Addresses**:
   - Address 1: Destination MAC (e.g., broadcast `FF:FF:FF:FF:FF:FF` or specific target).
   - Address 2: Source MAC (e.g., your device's MAC or a spoofed address).
   - Address 3: BSSID (e.g., the MAC of the access point).

3. **Add Frame Body**:
   - Include any additional data required for the frame type (e.g., SSID for Beacon frames).

4. **Calculate Frame Check Sequence (FCS)**:
   - Most tools and libraries (e.g., Scapy) handle this automatically.

## Creating Custom Raw Packets

### Python Example with Detailed Parameters

```python
from scapy.all import *

def create_custom_auth_packet(target_mac, ap_mac, seq_num=1):
    # RadioTap header with specific parameters
    radio = RadioTap(
        version=0,
        pad=0,
        len=13,
        present="Rate+Channel+dBm_AntSignal",
        Rate=2,  # 1 Mbps
        Channel=2412,  # Channel 1
        dBm_AntSignal=-50
    )
    
    # 802.11 header
    dot11 = Dot11(
        type="Management",
        subtype=11,  # Authentication
        addr1=target_mac,
        addr2=ap_mac,
        addr3=ap_mac,
        SC=(seq_num << 4)  # Sequence number
    )
    
    # Authentication body
    auth = Dot11Auth(
        algo=0,  # Open System
        seqnum=1,  # First frame
        status=0  # Successful
    )
    
    return radio/dot11/auth

# Example usage
packet = create_custom_auth_packet(
    target_mac="00:11:22:33:44:55",
    ap_mac="AA:BB:CC:DD:EE:FF",
    seq_num=1
)
```

### Raw Packet Construction Tips

1. **Frame Control Manipulation**
   ```python
   # Manual frame control field construction
   frame_control = int('1011000000000000', 2).to_bytes(2, byteorder='little')
   ```

2. **Address Field Formatting**
   ```python
   def mac_to_bytes(mac_str):
       return bytes.fromhex(mac_str.replace(':', ''))
   ```

3. **Sequence Control**
   ```python
   # Fragment number (4 bits) + Sequence number (12 bits)
   seq_control = ((sequence_num & 0xFFF) << 4).to_bytes(2, byteorder='little')
   ```

## Advanced Packet Crafting

### Custom Frame Body Elements
```python
def create_custom_ie(id_num, data):
    """Create custom Information Element"""
    return bytes([id_num, len(data)]) + data
```

### Channel Configuration
```python
def set_channel(iface, channel):
    """Set wireless interface channel"""
    os.system(f"iwconfig {iface} channel {channel}")
```

## Common Debugging Tips

1. **Packet Validation**
   - Check frame control values
   - Verify address fields
   - Confirm sequence numbers

2. **Common Issues**
   - Invalid FCS
   - Wrong channel
   - Incorrect timing
   - Missing RadioTap headers

## Tools for Analysis

1. **Wireshark Filters**
   ```
   wlan.fc.type == 0  # Management frames
   wlan.fc.type == 1  # Control frames
   wlan.fc.type == 2  # Data frames
   ```

2. **tcpdump Commands**
   ```bash
   tcpdump -i wlan0mon -e -s 0 type mgt
   ```

## Security Warning

This information is provided for educational purposes only. Unauthorized network interference is illegal in most jurisdictions. Always:
1. Obtain explicit permission before testing
2. Use in controlled environments
3. Follow local laws and regulations
4. Document all testing activities
5. Never use these techniques on networks without authorization
