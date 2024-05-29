#!/bin/bash

# به‌روزرسانی بسته‌ها و نصب پایتون 3 و pip
sudo apt update
sudo apt install -y python3 python3-pip

# نصب ماژول‌های مورد نیاز پایتون
pip3 install python-nmap

# نصب tkinter (بسته GUI برای پایتون)
sudo apt install -y python3-tk

echo "All required packages have been installed."
