#!/bin/bash
# Clone repository if it doesn't exist
if [ ! -d "simple-iot-scanner" ]; then
  git clone https://github.com/YashKantheti/simple-iot-scanner.git
  cd simple-iot-scanner
else
  cd simple-iot-scanner
  git pull
fi
# Run the scanner
sudo python3 main.py
