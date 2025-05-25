 # Traceroute Visualizer

A Python application that visualizes network routes using traceroute and displays them on an interactive map. The application provides a graphical user interface to trace routes to any domain or IP address and shows the path on a world map.

<img src="/screenshots/screenshot-2.png">

## Features

<img src="/screenshots/screenshot-1.png" width="450" height="400">
- Interactive GUI for entering target domains or IP addresses
- Real-time progress tracking with a progress bar
- Console log showing detailed traceroute information
- Interactive map visualization of the network route
- Automatic geolocation of network hops
- Support for up to 30 hops in the traceroute

## Requirements

- Python 3.6 or higher
- Required Python packages (install using `pip install -r requirements.txt`):
  - scapy
  - folium
  - requests

## Installation

1. Clone this repository or download the source code
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```
2. Enter a domain name or IP address in the input field
3. Click the "Traceroute" button
4. Wait for the traceroute to complete
5. The application will automatically open your default web browser with the route visualization

## How it Works

The application performs the following steps:
1. Sends ICMP packets with increasing TTL values to trace the route
2. Retrieves geolocation information for each hop using the IP-API service
3. Creates an interactive map using Folium
4. Displays the route with markers for each hop and lines connecting them

## Notes

- The application requires internet connectivity to perform traceroutes and fetch geolocation data
- Some networks may block ICMP packets, which could affect the traceroute results
- The geolocation service has rate limits and may not always return accurate data

## License

This project is open source and available under the MIT License. 
