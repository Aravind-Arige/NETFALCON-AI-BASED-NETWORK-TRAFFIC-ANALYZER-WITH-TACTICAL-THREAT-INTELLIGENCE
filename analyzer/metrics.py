import time
from collections import defaultdict


class Metrics:
    def __init__(self):
        self.start_time = time.time()
        self.total_bytes = 0
        self.packet_times = []
        self.protocols = defaultdict(int)
        self.packets = 0
        self.timestamps = [] # List of (timestamp, length) tuples
        self._packet_count = 0
        self._error_count = 0
        self.error_timestamps = []

    def update(self, packet_length: int, protocol: str = None, is_error: bool = False):
        """
        Called once per packet
        """
        now = time.time()

        self._packet_count += 1
        self.total_bytes += packet_length
        self.timestamps.append((now, packet_length))
        self.packet_times.append(now)

        if is_error:
            self._error_count += 1
            self.error_timestamps.append(now)

        if protocol:
            self.protocols[protocol] += 1

        # Keep a window of last 10 seconds, cap at 10,000 for safety
        while len(self.timestamps) > 10000 or (len(self.timestamps) > 0 and now - self.timestamps[0][0] > 10):
            self.timestamps.pop(0)

        while len(self.error_timestamps) > 0 and now - self.error_timestamps[0] > 10:
            self.error_timestamps.pop(0)
            
        if len(self.packet_times) > 100:
            self.packet_times.pop(0)

    @property
    def packet_count(self):
        return self._packet_count

    def bandwidth(self):
        """Returns instantaneous bandwidth in KB/s"""
        if len(self.timestamps) < 2:
            return 0
        
        duration = self.timestamps[-1][0] - self.timestamps[0][0]
        if duration <= 0:
            return 0.0
        
        window_bytes = sum(p[1] for p in self.timestamps)
        return round((window_bytes / duration) / 1024, 2)

    def speed_bps(self):
        """Returns instantaneous speed in bits per second"""
        if len(self.timestamps) < 2:
            return 0
        
        duration = self.timestamps[-1][0] - self.timestamps[0][0]
        if duration <= 0:
            return 0.0
            
        window_bits = sum(p[1] for p in self.timestamps) * 8
        return round(window_bits / duration, 2)

    def formatted_speed(self):
        bps = self.speed_bps()
        if bps < 1000:
            return f"{bps} bps"
        if bps < 1000000:
            return f"{round(bps/1000, 2)} Kbps"
        return f"{round(bps/1000000, 2)} Mbps"

    def packet_rate_live(self):
        """Returns number of packets in the last 1 second"""
        now = time.time()
        count = 0
        # Iterate backwards through timestamps as they are sorted
        for i in range(len(self.timestamps) - 1, -1, -1):
            if now - self.timestamps[i][0] <= 1.0:
                count += 1
            else:
                break
        return count

    def error_rate(self):
        """Errors per second in the last 1 second"""
        now = time.time()
        count = 0
        for i in range(len(self.error_timestamps) - 1, -1, -1):
            if now - self.error_timestamps[i] <= 1.0:
                count += 1
            else:
                break
        return count

    def error_percentage(self):
        """Percentage of error packets relative to total packets in the window"""
        if not self.timestamps: return 0.0
        window_packets = len(self.timestamps)
        window_errors = len(self.error_timestamps)
        return round((window_errors / window_packets) * 100, 2)

    def latency(self):
        if len(self.packet_times) < 2:
            return 0
        diffs = [self.packet_times[i+1] - self.packet_times[i] 
                 for i in range(len(self.packet_times)-1)]
        return round(sum(diffs) / len(diffs) * 1000, 2)

    def jitter(self):
        if len(self.packet_times) < 3:
            return 0
        diffs = [self.packet_times[i+1] - self.packet_times[i] 
                 for i in range(len(self.packet_times)-1)]
        jitter = [abs(diffs[i+1] - diffs[i]) 
                 for i in range(len(diffs)-1)]
        return round(sum(jitter) / len(jitter) * 1000, 2) 

    def packet_loss(self):
        # Simplified packet loss calculation
        return 0.0

    def reset(self):
        """
        Call when starting a new analysis session
        """
        self._packet_count = 0
        self._error_count = 0
        self.total_bytes = 0
        self.timestamps.clear()
        self.packet_times.clear()
        self.error_timestamps.clear()
        self.protocols.clear()

    def summary(self):
        return {
            "bandwidth": self.bandwidth(),
            "network_speed": self.speed_bps(),
            "speed_text": self.formatted_speed(),
            "latency": self.latency(),
            "jitter": self.jitter(),
            "packets": self.packet_count,
            "error_rate": self.error_rate(),
            "error_percentage": self.error_percentage(),
            "total_errors": self._error_count,
            "protocols": dict(self.protocols),
            "packet_loss": self.packet_loss(),
            "packet_count": self.packet_count
        }

