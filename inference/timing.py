# CI/CDecoy --- Timing Model
# inference/src/timing.py
#
# Injects realistic latency so responses don't arrive suspiciously
# fast (or slow).
#
# NOTE: This class was originally defined at the bottom of response_filter.py.
# Extracted here so server.py's `from timing import TimingModel` resolves.

class TimingModel:
    """
    Model for realistic command response timing.

    Real servers have characteristic latency profiles:
    - Simple builtins: 1-5ms
    - File reads: 5-50ms (depends on size)
    - Process listing: 20-100ms
    - Network operations: 100ms-30s (timeouts)
    - Package managers: 500ms-60s

    The inference service already has inherent latency from LLM
    generation. This model tells the decoy how much ADDITIONAL
    delay to add (or whether the LLM was too slow and we need
    to log a warning).
    """

    # Target latencies in seconds by command category
    LATENCY_PROFILES = {
        "instant":  {"min": 0.001, "max": 0.005, "mean": 0.003},
        "fast":     {"min": 0.005, "max": 0.050, "mean": 0.020},
        "moderate": {"min": 0.050, "max": 0.300, "mean": 0.100},
        "slow":     {"min": 0.300, "max": 2.000, "mean": 0.800},
        "network":  {"min": 0.500, "max": 30.00, "mean": 3.000},
        "heavy":    {"min": 1.000, "max": 60.00, "mean": 5.000},
    }

    # Command -> category mapping
    COMMAND_CATEGORIES = {
        "instant": ["pwd", "whoami", "id", "hostname", "echo", "true",
                     "false", "cd", "export", "unset", "alias"],
        "fast":    ["ls", "cat", "head", "tail", "wc", "date", "uptime",
                     "uname", "env", "printenv", "basename", "dirname"],
        "moderate":["ps", "df", "free", "mount", "lsblk", "ip", "ss",
                    "netstat", "systemctl", "journalctl", "docker"],
        "slow":    ["find", "grep", "locate", "du", "tar", "zip",
                    "ansible", "terraform", "kubectl"],
        "network": ["ssh", "scp", "curl", "wget", "ping", "nmap",
                    "nc", "telnet", "dig", "nslookup"],
        "heavy":   ["apt", "yum", "pip", "npm", "make", "gcc",
                    "docker build", "docker pull"],
    }

    def get_target_latency(self, command: str) -> dict:
        """Return the target latency profile for a command."""
        cmd = command.split()[0] if command.split() else command

        for category, commands in self.COMMAND_CATEGORIES.items():
            if cmd in commands:
                return self.LATENCY_PROFILES[category]

        return self.LATENCY_PROFILES["moderate"]
