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

## ❌ 2. Deauthentication Frame

Sent to forcibly disconnect clients from the AP.

```cpp
uint8_t deauthPacket[26] = {
  0xC0, 0x00, // Frame Control: Deauth (Subtype: 12)
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0x00, 0x00,
  0x07, 0x00  // Reason Code: 7 (Class 3 frame received from nonassociated STA)
};
```

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
