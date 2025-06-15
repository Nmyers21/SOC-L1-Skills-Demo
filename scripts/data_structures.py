#!/usr/bin/env python3
"""
Basic data structures for security event handling
"""

class SecurityEvent:
    def __init__(self, timestamp, event_id, source_ip):
        self.timestamp = timestamp
        self.event_id = event_id
        self.source_ip = source_ip
        
if __name__ == "__main__":
    print("Security event data structures loaded")
