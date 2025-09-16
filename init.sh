#!/usr/bin/env bash
echo "Creating venv"
python3 -m venv .
echo "Starting venv"
source bin/activate
echo "Installing dependencies"
apt-get install tshark hcxtools
pip install -r requirements.txt
echo "FINISHED SETUP"
