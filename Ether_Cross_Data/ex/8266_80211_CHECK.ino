/*
 * ESP8266 Wi-Fi Management Frame Analyzer
 * Captures and analyzes 802.11 management frames in promiscuous mode
 */

#include <ESP8266WiFi.h>
extern "C" {
  #include "user_interface.h"
}

// Frame type and subtype definitions
#define FRAME_TYPE_MGMT 0x00
#define BEACON        0x08
#define PROBE_REQ     0x04
#define PROBE_RES     0x05
#define AUTH          0x0B
#define ASSOC_REQ     0x00
#define ASSOC_RES     0x01
#define REASSOC_REQ   0x02
#define REASSOC_RES   0x03
#define DISASSOC      0x0A
#define DEAUTH        0x0C
#define ACTION        0x0D

// Buffer for SSID extraction
char ssid[33];
uint8_t channel = 1;  // Default WiFi channel

// Add channel hopping variables
unsigned long lastChannelSwitch = 0;
const unsigned long CHANNEL_HOP_INTERVAL = 1000; // 1 second

// Structure to store frame statistics
struct FrameStats {
    unsigned long beacons;
    unsigned long probeReqs;
    unsigned long probeRes;
    unsigned long auth;
    unsigned long assocReq;
    unsigned long assocRes;
    unsigned long reassocReq;
    unsigned long reassocRes;
    unsigned long disassoc;
    unsigned long deauth;
    unsigned long action;
} stats = {0};

// Convert MAC address to string
String macToStr(const uint8_t* mac) {
    char macStr[18] = { 0 };
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}

// Get frame type alias
const char* getFrameAlias(uint8_t subtype) {
    switch(subtype) {
        case BEACON:      return "BEACON";
        case PROBE_REQ:   return "PROBE_REQ";
        case PROBE_RES:   return "PROBE_RES";
        case AUTH:        return "AUTH";
        case ASSOC_REQ:   return "ASSOC_REQ";
        case ASSOC_RES:   return "ASSOC_RES";
        case REASSOC_REQ: return "REASSOC_REQ";
        case REASSOC_RES: return "REASSOC_RES";
        case DISASSOC:    return "DISASSOC";
        case DEAUTH:      return "DEAUTH";
        case ACTION:      return "ACTION";
        default:         return "UNKNOWN";
    }
}

// Update statistics based on frame type
void updateStats(uint8_t subtype) {
    switch(subtype) {
        case BEACON:      stats.beacons++; break;
        case PROBE_REQ:   stats.probeReqs++; break;
        case PROBE_RES:   stats.probeRes++; break;
        case AUTH:        stats.auth++; break;
        case ASSOC_REQ:   stats.assocReq++; break;
        case ASSOC_RES:   stats.assocRes++; break;
        case REASSOC_REQ: stats.reassocReq++; break;
        case REASSOC_RES: stats.reassocRes++; break;
        case DISASSOC:    stats.disassoc++; break;
        case DEAUTH:      stats.deauth++; break;
        case ACTION:      stats.action++; break;
    }
}

// Extract SSID from beacon frames
String extractSSID(uint8_t *payload, uint16_t length) {
    if (length < 12) return "";  // Too short for SSID
    
    uint16_t pos = 36;  // Skip fixed parameters
    while (pos < length) {
        if (payload[pos] == 0x00) {  // SSID element ID
            uint8_t ssidLen = payload[pos + 1];
            if (ssidLen > 32 || pos + 2 + ssidLen > length) return "";
            memcpy(ssid, &payload[pos + 2], ssidLen);
            ssid[ssidLen] = '\0';
            return String(ssid);
        }
        pos += payload[pos + 1] + 2;  // Move to next element
    }
    return "";
}

// Promiscuous mode callback
void ICACHE_FLASH_ATTR promisc_cb(uint8_t *buf, uint16_t len) {
    if (len < 24) return;  // Frame too short
    
    struct RxControl {
        signed rssi:8;
        unsigned rate:4;
        unsigned is_group:1;
        unsigned:1;
        unsigned sig_mode:2;
        unsigned legacy_length:12;
        unsigned damatch0:1;
        unsigned damatch1:1;
        unsigned bssidmatch0:1;
        unsigned bssidmatch1:1;
        unsigned MCS:7;
        unsigned CWB:1;
        unsigned HT_length:16;
        unsigned Smoothing:1;
        unsigned Not_Sounding:1;
        unsigned:1;
        unsigned Aggregation:1;
        unsigned STBC:2;
        unsigned FEC_CODING:1;
        unsigned SGI:1;
        unsigned rxend_state:8;
        unsigned ampdu_cnt:8;
        unsigned channel:4;
        unsigned:12;
    } *rx_ctrl = (struct RxControl*)buf;

    uint8_t *frame = buf + sizeof(struct RxControl);
    uint8_t frame_type = (frame[0] & 0x0C) >> 2;
    uint8_t frame_subtype = (frame[0] & 0xF0) >> 4;

    // Only process management frames
    if (frame_type != FRAME_TYPE_MGMT) return;

    // Update frame statistics
    updateStats(frame_subtype);

    // Extract addresses
    String src_mac = macToStr(&frame[10]);
    String dst_mac = macToStr(&frame[4]);

    // Format and send the output
    String output = String("[") + getFrameAlias(frame_subtype) + 
                   "] RSSI:" + String(rx_ctrl->rssi) +
                   " SRC:" + src_mac +
                   " DST:" + dst_mac;

    // Add SSID for beacon and probe response frames
    if (frame_subtype == BEACON || frame_subtype == PROBE_RES) {
        String ssid = extractSSID(frame, len);
        if (ssid.length() > 0) {
            output += " SSID:\"" + ssid + "\"";
        }
    }

    // Send formatted output
    Serial.println(output);
}

void switchChannel() {
    channel = (channel % 13) + 1; // Cycle through channels 1-13
    wifi_set_channel(channel);
    Serial.println("CHANNEL|" + String(channel));
}

void setup() {
    // Initialize Serial with specified baud rate
    Serial.begin(115200);
    while (!Serial) {
        delay(100);  // Wait for serial connection
    }

    // Disable WiFi to prepare for promiscuous mode
    WiFi.disconnect();
    WiFi.mode(WIFI_OFF);
    delay(100);

    // Enable promiscuous mode
    wifi_set_opmode(STATION_MODE);
    wifi_set_channel(channel);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(promisc_cb);
    wifi_promiscuous_enable(1);

    Serial.println("START|ESP8266 Frame Analyzer Ready");
}

unsigned long lastStats = 0;
const unsigned long STATS_INTERVAL = 5000;  // 5 seconds

void loop() {
    // Non-blocking stats output every 5 seconds
    if (millis() - lastStats >= STATS_INTERVAL) {
        String stats_output = "STATS|" +
            String(stats.beacons) + "," +
            String(stats.probeReqs) + "," +
            String(stats.probeRes) + "," +
            String(stats.auth) + "," +
            String(stats.assocReq) + "," +
            String(stats.assocRes) + "," +
            String(stats.reassocReq) + "," +
            String(stats.reassocRes) + "," +
            String(stats.disassoc) + "," +
            String(stats.deauth) + "," +
            String(stats.action);
        
        Serial.println(stats_output);
        lastStats = millis();
    }

    // Channel hopping every 1 second
    if (millis() - lastChannelSwitch >= CHANNEL_HOP_INTERVAL) {
        switchChannel();
        lastChannelSwitch = millis();
    }

    // Allow ESP8266 to handle background tasks
    delay(1);
}
