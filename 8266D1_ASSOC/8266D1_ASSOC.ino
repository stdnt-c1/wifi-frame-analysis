#include "../ESP8266_80211.h"

// Create instance of the helper class
ESP8266_80211 wifi80211(1);  // Initialize with channel 1

// Buffer for the authentication frame
uint8_t authPacket[AUTH_FRAME_LEN];

void setup() {
  Serial.begin(115200);
  delay(1000);  // Wait for serial to initialize

  if (!wifi80211.begin()) {
    Serial.println("Failed to initialize WiFi!");
    while(1) delay(1000);
  }

  // Create the authentication frame
  wifi80211.createAuthenticationFrame(authPacket);
  
  Serial.println("Setup complete, sending Authentication frames...");
}

void loop() {
  // Always (re)build the frame before sending
  wifi80211.createAuthenticationFrame(authPacket);
  int result = wifi_send_pkt_freedom(authPacket, sizeof(authPacket), 0);
  if (result != 0) {
    Serial.printf("Failed to send packet. Error: %d\n", result);
    for (unsigned int i = 0; i < sizeof(authPacket); i++) {
      Serial.printf("%02X ", authPacket[i]);
    }
    Serial.println();
    switch(result) {
      case -1:
        Serial.println("Error: Invalid packet length or null pointer");
        break;
      case -2:
        Serial.println("Error: Packet too long");
        break;
      case -3:
        Serial.println("Error: Busy, previous packet not finished");
        break;
      case -4:
        Serial.println("Error: Invalid arguments");
        break;
      default:
        Serial.println("Error: Unknown error");
    }
  } else {
    Serial.println("Successfully sent packet");
  }
  delay(50);  // 50ms delay between packets
}
