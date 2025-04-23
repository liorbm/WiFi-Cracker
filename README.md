# WiFi-Cracker

A powerful and user-friendly tool for capturing WPA/WPA2 handshakes and cracking WiFi passwords. This tool automates the process of network scanning, handshake capture, and password cracking with a beautiful colored interface.

## Features

- 🎨 Beautiful colored interface with vibrant output
- 📡 Automatic wireless interface detection and monitor mode setup
- 🔍 Network scanning with detailed information display
- 🤝 Automated handshake capture with deauthentication attack
- 🔑 Multiple password cracking methods:
  - Israeli phone numbers wordlist generation
  - Custom wordlist support
- 🖥️ Colored xterm windows for real-time monitoring
- 🧹 Automatic cleanup of processes.

## Requirements

- Linux-based operating system (preferably Kali Linux)
- Root privileges
- Wireless interface supporting monitor mode
- Required tools:
  - aircrack-ng (includes airodump-ng, aireplay-ng, and airmon-ng)
  - crunch
  - xterm
  - figlet

## Installation

1. Clone the repository:
```bash
git clone https://github.com/liorbm/WiFi-Cracker.git
cd WiFi-Cracker
```

2. Make the script executable:
```bash
chmod +x WiFi-Cracker.sh
```

## Usage

1. Run the script with root privileges:
```bash
sudo ./WiFi-Cracker.sh
```

2. Follow the on-screen instructions:
   - Select target network from the list
   - Wait for handshake capture
   - Choose password cracking wordlist
   - Wait for results

## Notes

- This tool is for educational purposes only
- Always ensure you have permission to test networks
- The tool requires a compatible wireless interface
- Some features may require additional dependencies
- Kali Linux VM's are using the CPU to run wordlists,
  So - be patient because its slower than a GPU usage.
- To crack a WPA handshake with a GPU, convert the .cap to .hc22000
  and use Hashcat on Windows for better GPU performance and stability

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

- Lior Biam
- GitHub: [@liorbm](https://github.com/liorbm)

## Disclaimer

This tool is provided for educational purposes only. The author is not responsible for any misuse or damage caused by this program. Always ensure you have permission to test networks and comply with local laws and regulations. 
