# CloudBlower
CloudBlower a very generic IOS Fuzzer made with features such as multi threading and randomizing. 

Installation: git clone https://github.com/ghostsec420/CloudBlower

usage: cloudblower.py [-h] [--ip IP] [--port PORT] [--rounds ROUNDS] [--log LOG] [--threads THREADS] [--sleep SLEEP]

iOS ASLR Bypass/Fuzzer

options:
  -h, --help         show this help message and exit
  --ip IP            Target IP address
  --port PORT        Target port
  --rounds ROUNDS    Number of fuzz rounds
  --log LOG          Leak log file
  --threads THREADS  Number of concurrent threads
  --sleep SLEEP      Sleep time between rounds (seconds)
