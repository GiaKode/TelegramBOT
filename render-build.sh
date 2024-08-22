#!/usr/bin/env bash

# Instala zbar para pyzbar
sudo apt-get update && sudo apt-get install -y libzbar0

# Luego procede con la instalación de las dependencias de Python
pip install -r requirements.txt
