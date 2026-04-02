import socket
import time
import threading

# Target: Google DNS (safe, drops unsolicited UDP)
TARGET_IP = "8.8.8.8" 
TARGET_PORT = 53
DURATION = 5 # seconds

def send_burst():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + DURATION
    count = 0
    print(f"[*] Sending high-rate traffic to {TARGET_IP} for {DURATION}s...")
    
    while time.time() < end_time:
        try:
            # Send small UDP packets rapidly
            sock.sendto(b"DOS_TEST_PACKET", (TARGET_IP, TARGET_PORT))
            count += 1
            # Slight delay to allow other threads or system to breathe, 
            # but small enough to exceed 100 packets/sec
            time.sleep(0.002) 
        except Exception as e:
            print(f"Error: {e}")
            break
    print(f"[*] Thread finished. Sent {count} packets.")

if __name__ == "__main__":
    print("[!] Starting DoS Simulation Script")
    print("[!] Check your Dashboard 'Threats' section for alerts.")
    
    # Run multiple threads to ensure we hit the packet rate threshold
    threads = []
    for _ in range(3):
        t = threading.Thread(target=send_burst)
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    print("[!] Simulation complete.")
