#!/usr/bin/env python3
"""
Security event data generation for SOC analysis
"""
import json
from datetime import datetime, timedelta

# Define basic security event types
EVENT_TYPES = {
    'failed_logon': {'event_id': '4625', 'severity': 'medium'},
    'successful_logon': {'event_id': '4624', 'severity': 'low'},
    'privilege_assigned': {'event_id': '4672', 'severity': 'high'},
    'account_created': {'event_id': '4720', 'severity': 'high'},
    'process_creation': {'event_id': '4688', 'severity': 'medium'}
}

def create_sample_events():
    events = []
    base_time = datetime.now()
    
    # Create basic event structure
    sample_event = {
        'timestamp': base_time.isoformat(),
        'event_id': '4625',
        'source_ip': '10.0.1.100',
        'username': 'testuser',
        'hostname': 'WORKSTATION-01',
        'description': 'Sample security event'
    }
    events.append(sample_event)
    
    return events

if __name__ == "__main__":
    events = create_sample_events()
    print(f"Generated {len(events)} security events")
    print(f"Event types available: {len(EVENT_TYPES)}")
