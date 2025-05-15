---

# 📡 802.11 Management, Control, and Data Frames - Raw Packet Definitions

This document details the structure of various **802.11 raw frames** used in wireless communication, particularly useful for ESP8266/ESP32 devices in packet injection, sniffing, or Wi-Fi deauth/penetration testing scenarios.

All frames typically use:

* **Destination Address (DA)**: `FF:FF:FF:FF:FF:FF` (Broadcast)
* **Source Address (SA)**: The MAC address of the sender (ESP device)
* **BSSID**: MAC of the access point (or spoofed)

---

## 🔒 1. Authentication Frame

Used by clients to initiate connection to an access point.

```cpp
uint8_t authPacket[26] = {
  0xB0, 0x00, // Frame Control: Authentication (Type: Mgmt, Subtype: 11)
  0x00, 0x00, // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination Address
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Source Address
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // BSSID
  0x00, 0x00, // Sequence Control
  0x00, 0x00  // Authentication Algorithm: Open System
};
```

---

## Updated Authentication Frame Structure (2025)

## Total Frame Size: 38 bytes

### 1. RadioTap Header (8 bytes)
```
+------------------+----------------+----------------------+
| Field            | Size (bytes)   | Value (Hex)         |
+------------------+----------------+----------------------+
| Version          | 1             | 0x00                |
| Pad             | 1             | 0x00                |
| Length          | 2             | 0x08 0x00           |
| Present flags   | 4             | 0x00 0x00 0x00 0x00 |
```

### 2. 802.11 Header (24 bytes)
```
+------------------+----------------+--------------------------------+
| Field            | Size (bytes)   | Value (Hex) + Description     |
+------------------+----------------+--------------------------------+
| Frame Control    | 2             | 0xB0 0x00 (Auth frame)        |
| Duration         | 2             | 0x3A 0x01 (314us)             |
| Address 1        | 6             | Destination (usually broadcast) |
| Address 2        | 6             | Source MAC (ESP MAC)           |
| Address 3        | 6             | BSSID (ESP MAC)               |
| Sequence Control | 2             | 0x00 0x00                     |
```

### 3. Authentication Body (6 bytes)
```
+------------------+----------------+--------------------------------+
| Field            | Size (bytes)   | Value (Hex) + Description     |
+------------------+----------------+--------------------------------+
| Auth Algorithm   | 2             | 0x00 0x00 (Open System)       |
| Auth Sequence    | 2             | 0x01 0x00 (First frame)       |
| Status Code      | 2             | 0x00 0x00 (Success)           |
```

### Important Notes:
1. The RadioTap header is minimized to 8 bytes to reduce complexity
2. Duration field is set to 314us (0x013A) as a standard value
3. MAC addresses must be properly copied after header offset (RadioTap length)
4. Packet must be exactly 38 bytes for proper transmission

---

## ❌ 2. Deauthentication Frame (Updated)

| Field               | Bytes | Value (Hex) | Description                              |
|---------------------|-------|-------------|------------------------------------------|
| RadioTap Header     | 12    | See below   | Contains metadata for transmission       |
| Frame Control       | 2     | `C0 00`     | Deauthentication frame                  |
| Duration/ID         | 2     | `00 00`     | Typically 0                              |
| Address 1 (Dest)    | 6     | `FF FF FF FF FF FF` | Broadcast                               |
| Address 2 (Source)  | 6     | `AA BB CC DD EE FF` | Source MAC (ESP MAC)                   |
| Address 3 (BSSID)   | 6     | `AA BB CC DD EE FF` | BSSID (ESP MAC)                        |
| Sequence Control    | 2     | `00 00`     | Sequence number                          |
| Frame Body          | 2     | `07 00`     | Reason Code (7: Class 3 frame received)  |

#### RadioTap Header Details

| Field               | Bytes | Value (Hex) | Description                              |
|---------------------|-------|-------------|------------------------------------------|
| Version + Pad       | 2     | `00 00`     | Version and padding                     |
| Length              | 2     | `0C 00`     | Total length of the RadioTap header     |
| Present Flags       | 4     | `04 80 00 00` | Indicates which fields are present     |
| Rate                | 2     | `02 00`     | Transmission rate (1 Mbps)              |
| TX Flags            | 2     | `18 00`     | Transmission flags                      |

### Notes

- The deauthentication packet now includes a RadioTap header for proper transmission.
- The ESP8266's MAC address is dynamically inserted into the packet for both the source and BSSID fields.
- The refined structure ensures compatibility with the `wifi_send_pkt_freedom` function.

---

## 📥 3. Association Request Frame

Sent by a client to an AP after authentication.

```cpp
uint8_t assocReqPacket[26] = {
  0x00, 0x00, // Frame Control: Association Request
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0x00, 0x00,
  0x00, 0x00  // Capability Information
};
```

---

## 🔌 4. Disassociation Frame

Client/AP uses this to end a connection gracefully.

```cpp
uint8_t disassocPacket[26] = {
  0xA0, 0x00, // Frame Control: Disassociation
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0x00, 0x00,
  0x08, 0x00  // Reason Code: Leaving BSS
};
```

---

## 📡 5. Probe Request Frame

Sent by clients to scan nearby APs.

```cpp
uint8_t probeReqPacket[26] = {
  0x40, 0x00, // Frame Control: Probe Request
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID: Broadcast
  0x00, 0x00
};
```

---

## 📶 6. Probe Response Frame

Sent by APs in response to a probe request.

```cpp
uint8_t probeRespPacket[38] = {
  0x50, 0x00, // Frame Control: Probe Response
  0x00, 0x00,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Destination
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Source (AP)
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // BSSID
  0x00, 0x00,
  0x64, 0x00, 0x01, 0x04, 0x00, 0x00, // Timestamp + Beacon Interval
  0x01, 0x04, 0x82, 0x84, 0x8B, 0x96  // Supported Rates (example)
};
```

---

## 📻 7. Beacon Frame

APs periodically send this to announce their presence.

```cpp
uint8_t beaconPacket[38] = {
  0x80, 0x00, // Frame Control: Beacon
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
  0x00, 0x00,
  0x64, 0x00, 0x01, 0x04, 0x00, 0x00, // Timestamp, Interval
  0x01, 0x04, 0x82, 0x84, 0x8B, 0x96  // Supported Rates
};
```

---

## ✅ 8. ACK Frame

Acknowledges receipt of a frame, sent by receivers.

```cpp
uint8_t ackPacket[16] = {
  0xD4, 0x00, // Frame Control: ACK
  0x00, 0x00,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Receiver Address
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding (optional)
  0x00, 0x00
};
```

---

## 💾 9. Data Frame

Used to transmit actual payloads over the network.

```cpp
uint8_t dataFrame[34] = {
  0x08, 0x00, // Frame Control: Data
  0x00, 0x00,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // Destination
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Source
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // BSSID
  0x00, 0x00, // Sequence Control
  0xDE, 0xAD, 0xBE, 0xEF              // Payload example
};
```

---

## ⚙️ Transmission Configuration Example

To transmit raw frames using ESP devices:

```cpp
void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(1);
  system_phy_set_max_tpw(82);
  noInterrupts();
  Serial.println("WiFi TX Setup Complete");
}

void loop() {
  int result = wifi_send_pkt_freedom(beaconPacket, sizeof(beaconPacket), 0);
  if (result != 0) {
    Serial.printf("Failed to send packet. Error: %d\n", result);
  }
}
```

---

## 🧱 Notes on Frame Control Byte (Little Endian)

| Frame Type | Subtype | Control Bytes       |
| ---------- | ------- | ------------------- |
| Management | 0x00    | Association Request |
| Management | 0x04    | Probe Request       |
| Management | 0x08    | Beacon              |
| Management | 0x0B    | Authentication      |
| Management | 0x0C    | Deauthentication    |
| Control    | 0x1D    | ACK                 |
| Data       | 0x08    | Data                |

---
