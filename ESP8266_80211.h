/*
 * ESP8266 802.11 Frame Construction Helper
 * Created: May 15, 2025
 * This header file provides structures and functions for creating various 802.11 frames
 */

#ifndef ESP8266_80211_H
#define ESP8266_80211_H

#include <ESP8266WiFi.h>
extern "C" {
  #include "user_interface.h"
}

// Define packet sizes and constants
#define RADIOTAP_LEN 8
#define MAC_ADDR_LEN 6
#define HEADER_80211_LEN 24
#define AUTH_FRAME_LEN 38  // RadioTap(8) + 802.11(24) + Auth(6)
#define DEAUTH_FRAME_LEN 34  // RadioTap(8) + 802.11(24) + Reason(2)
#define BEACON_FRAME_LEN 68

// Frame subtypes
#define IEEE80211_STYPE_ASSOC_REQ    0x00
#define IEEE80211_STYPE_ASSOC_RESP   0x10
#define IEEE80211_STYPE_REASSOC_REQ  0x20
#define IEEE80211_STYPE_REASSOC_RESP 0x30
#define IEEE80211_STYPE_PROBE_REQ    0x40
#define IEEE80211_STYPE_PROBE_RESP   0x50
#define IEEE80211_STYPE_BEACON       0x80
#define IEEE80211_STYPE_ATIM         0x90
#define IEEE80211_STYPE_DISASSOC     0xA0
#define IEEE80211_STYPE_AUTH         0xB0
#define IEEE80211_STYPE_DEAUTH       0xC0

class ESP8266_80211 {
  private:
    uint8_t channel;
    uint8_t mac[MAC_ADDR_LEN];
    bool promiscuous_enabled;

    // RadioTap header template
    const uint8_t radioTapHeader[RADIOTAP_LEN] = {
      0x00, 0x00,             // Version + Pad
      0x08, 0x00,             // Length
      0x00, 0x00, 0x00, 0x00  // Present flags
    };

  public:
    ESP8266_80211(uint8_t wifi_channel = 1) {
      channel = wifi_channel;
      promiscuous_enabled = false;
      
      // Get ESP's MAC address
      wifi_get_macaddr(STATION_IF, mac);
    }

    bool begin() {
      // Initialize WiFi in the correct mode
      WiFi.mode(WIFI_OFF);
      delay(100);
      WiFi.mode(WIFI_STA);
      
      // Enable promiscuous mode
      if (!promiscuous_enabled) {
        wifi_promiscuous_enable(1);
        promiscuous_enabled = true;
      }
      
      // Set channel
      wifi_set_channel(channel);
      
      // Set max TX power
      system_phy_set_max_tpw(82);
      
      return true;
    }    void createAuthenticationFrame(uint8_t* packet) {
      // Zero out buffer and ensure alignment
      memset(packet, 0, AUTH_FRAME_LEN);

      // RadioTap Header (8 bytes, aligned)
      memcpy(packet, radioTapHeader, RADIOTAP_LEN);

      // 802.11 Frame (aligned to 16-bit boundary)
      uint8_t* frame = packet + RADIOTAP_LEN;
      uint16_t* frame16 = (uint16_t*)frame;

      // Frame Control Field (2 bytes)
      frame16[0] = IEEE80211_STYPE_AUTH;  // Authentication frame

      // Duration ID (2 bytes)
      frame16[1] = 314;  // Duration 314μs

      // Address Fields (6 bytes each, aligned)
      memset(&frame[4], 0xFF, MAC_ADDR_LEN);   // Address 1: Destination (broadcast)
      memcpy(&frame[10], mac, MAC_ADDR_LEN);   // Address 2: Source
      memcpy(&frame[16], mac, MAC_ADDR_LEN);   // Address 3: BSSID

      // Sequence Control (2 bytes)
      frame16[11] = 0;  // Sequence number will be filled by hardware

      // Authentication Algorithm (2 bytes)
      frame16[12] = 0;  // Open System

      // Authentication Sequence (2 bytes)
      frame16[13] = 1;  // First frame in sequence

      // Status Code (2 bytes)
      frame16[14] = 0;  // Success
    }    void createDeauthenticationFrame(uint8_t* packet, uint16_t reason = 7) {
      // Zero out buffer and ensure alignment
      memset(packet, 0, DEAUTH_FRAME_LEN);

      // RadioTap Header (8 bytes, aligned)
      memcpy(packet, radioTapHeader, RADIOTAP_LEN);

      // 802.11 Frame (aligned to 16-bit boundary)
      uint8_t* frame = packet + RADIOTAP_LEN;
      uint16_t* frame16 = (uint16_t*)frame;

      // Frame Control Field (2 bytes)
      frame16[0] = IEEE80211_STYPE_DEAUTH;  // Deauthentication frame

      // Duration ID (2 bytes)
      frame16[1] = 0;  // No duration for deauth

      // Address Fields (6 bytes each, aligned)
      memset(&frame[4], 0xFF, MAC_ADDR_LEN);   // Address 1: Destination (broadcast)
      memcpy(&frame[10], mac, MAC_ADDR_LEN);   // Address 2: Source
      memcpy(&frame[16], mac, MAC_ADDR_LEN);   // Address 3: BSSID

      // Sequence Control (2 bytes)
      frame16[11] = 0;  // Sequence number will be filled by hardware

      // Reason Code (2 bytes)
      frame16[12] = reason;  // Little-endian by default
    }

    bool sendPacket(uint8_t* packet, size_t size) {
      int result = wifi_send_pkt_freedom(packet, size, 0);
      if (result == 0) {
        return true;
      }
      Serial.printf("Send failed with error: %d\n", result);
      return false;
    }

    void setChannel(uint8_t new_channel) {
      if (new_channel >= 1 && new_channel <= 14) {
        channel = new_channel;
        wifi_set_channel(channel);
      }
    }

    uint8_t getChannel() {
      return channel;
    }

    void getMac(uint8_t* mac_out) {
      memcpy(mac_out, mac, MAC_ADDR_LEN);
    }
};

#endif // ESP8266_80211_H
