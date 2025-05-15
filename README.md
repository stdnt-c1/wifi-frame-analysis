# WiFi Frame Analysis Tools

A comprehensive suite of tools for capturing, analyzing, and displaying 802.11 management frames using ESP8266, Ubuntu, and Windows systems.

## Project Structure

```
├── 80211_Complete_Frame_Reference.pdf
├── 80211_management_frames.md
├── 8266D1_ASSOC/
│   └── 8266D1_ASSOC.ino          # ESP8266 Association frame generator
├── 8266D1_DEAUTH_JAM/
│   └── 8266D1_DEAUTH_JAM.ino     # ESP8266 Deauthentication frame generator
└── Ether_Cross_Data/
    ├── simple_guide.txt          # Guide for direct ethernet connection
    └── ex/
        ├── 8266_80211_CHECK.ino  # ESP8266 frame analyzer example
        ├── display_frames.py     # Serial-based frame display
        ├── display_frames_net.py # Network-based frame display
        └── wifi_capture.py      # Ubuntu frame capture script
```

## Components

### 1. Frame Reference Documentation
- `80211_Complete_Frame_Reference.pdf`: Comprehensive reference for 802.11 frames
- `80211_management_frames.md`: Detailed specifications for management frame structures

### 2. ESP8266 Tools
- **Association Generator**: Generate association requests for testing
- **Deauthentication Generator**: Generate deauthentication frames
- **Frame Analyzer**: Monitor and analyze 802.11 frames in vicinity

### 3. Cross-Platform Analysis System
- **Ubuntu Capture Script**: Captures frames using wireless interface in monitor mode
- **Windows Display Script**: Real-time visualization of captured frames
- **Network Bridge**: Direct ethernet connection between systems for data streaming

## Requirements

### ESP8266 Requirements
- Arduino IDE with ESP8266 board support
- ESP8266 development board
- USB cable for programming

### Ubuntu Requirements
- Python 3.x
- Scapy library (`pip3 install scapy`)
- Wireless interface supporting monitor mode
- Root privileges for monitor mode

### Windows Requirements
- Python 3.x
- Rich library (`pip install rich`)
- Ethernet port for direct connection

## Setup Instructions

### ESP8266 Setup
1. Install ESP8266 board support in Arduino IDE
2. Select appropriate board and port
3. Upload desired sketch (Association, Deauth, or Analyzer)

### Ubuntu Setup
1. Connect to Windows PC via ethernet
2. Enable monitor mode on wireless interface:
   ```bash
   sudo airmon-ng check kill
   sudo airmon-ng start <interface>
   ```
3. Start capture script:
   ```bash
   sudo python3 wifi_capture.py <monitor_interface> --ip <ubuntu_ip>
   ```

### Windows Setup
1. Connect to Ubuntu PC via ethernet
2. Start display script:
   ```cmd
   python display_frames_net.py <ubuntu_ip>
   ```

## Frame Types Supported

- Authentication
- Deauthentication
- Association Request/Response
- Reassociation Request/Response
- Probe Request/Response
- Beacon
- Disassociation
- Action

## Features

- Real-time frame capture and analysis
- Cross-platform support
- Rich CLI interface with live updates
- Frame type filtering
- Frame statistics
- RSSI monitoring
- MAC address tracking
- SSID detection
- Raw data logging

## Security Notice

This toolkit is designed for educational and network analysis purposes only. Users must:
1. Obtain necessary permissions before monitoring any network
2. Comply with local laws and regulations
3. Use responsibly and ethically
4. Not use for malicious purposes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
