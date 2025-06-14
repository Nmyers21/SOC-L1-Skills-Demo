#!/usr/bin/env python3
"""
Security event data generation for SOC analysis
Author: Noah Myers
"""
import json
from datetime import datetime, timedelta
import random

# Define basic security event types
EVENT_TYPES = {
    'failed_logon': {'event_id': '4625', 'severity': 'medium'},
    'successful_logon': {'event_id': '4624', 'severity': 'low'},
    'privilege_assigned': {'event_id': '4672', 'severity': 'high'},
    'account_created': {'event_id': '4720', 'severity': 'high'},
    'process_creation': {'event_id': '4688', 'severity': 'medium'},
    'network_connection': {'event_id': '3', 'severity': 'medium'},
    'file_creation': {'event_id': '11', 'severity': 'low'}
}

class SecurityEventGenerator:
    def __init__(self):
        self.internal_ips = ["10.0.1.", "192.168.1.", "172.16.0."]
        self.external_ips = ["203.0.113.", "198.51.100.", "185.220.100."]
        self.admin_accounts = ["admin", "administrator", "domainadmin"]
        self.regular_users = ["jdoe", "msmith", "bwilson", "skumar", "achen"]
        self.service_accounts = ["svc_backup", "svc_sql", "svc_web"]
        self.workstations = ["WORKSTATION-01", "WORKSTATION-02", "WORKSTATION-03", "WS-04", "WS-05"]
        self.servers = ["SERVER-01", "DC-01", "FILE-SRV-01"]
        
    def generate_brute_force_scenario(self, base_time):
        """Generate realistic brute force attack events"""
        events = []
        attack_ip = "203.0.113.45"
        target_accounts = ["admin", "administrator"]
        
        # 15 failed attempts over 3 minutes
        for i in range(15):
            event_time = base_time + timedelta(seconds=i * 12)
            target_user = random.choice(target_accounts)
            
            event = {
                'timestamp': event_time.isoformat() + 'Z',
                'event_id': '4625',
                'severity': 'medium',
                'source_ip': attack_ip,
                'username': target_user,
                'hostname': 'WORKSTATION-01',
                'description': f'Failed authentication attempt for {target_user}',
                'failure_reason': '0xC000006A',  # Bad password
                'logon_type': '3',  # Network logon
                'process_name': 'winlogon.exe',
                'mitre_technique': 'T1110.001'
            }
            events.append(event)
            
        # One successful logon after the attack (compromise)
        success_time = base_time + timedelta(minutes=4)
        success_event = {
            'timestamp': success_time.isoformat() + 'Z',
            'event_id': '4624',
            'severity': 'high',
            'source_ip': attack_ip,
            'username': 'administrator',
            'hostname': 'WORKSTATION-01',
            'description': 'Successful logon after brute force attack',
            'logon_type': '3',
            'process_name': 'winlogon.exe',
            'mitre_technique': 'T1078'
        }
        events.append(success_event)
        
        return events
    
    def generate_privilege_escalation_scenario(self, base_time):
        """Generate privilege escalation attack chain"""
        events = []
        
        # Normal user logon
        logon_time = base_time + timedelta(minutes=10)
        logon_event = {
            'timestamp': logon_time.isoformat() + 'Z',
            'event_id': '4624',
            'severity': 'low',
            'source_ip': '10.0.1.100',
            'username': 'intern',
            'hostname': 'WORKSTATION-03',
            'description': 'Standard user logon',
            'logon_type': '2',  # Interactive logon
            'process_name': 'winlogon.exe',
            'mitre_technique': 'T1078'
        }
        events.append(logon_event)
        
        # Privilege assignment (escalation)
        priv_time = base_time + timedelta(minutes=12)
        priv_event = {
            'timestamp': priv_time.isoformat() + 'Z',
            'event_id': '4672',
            'severity': 'critical',
            'source_ip': '10.0.1.100',
            'username': 'intern',
            'hostname': 'WORKSTATION-03',
            'description': 'Special privileges assigned to standard user',
            'privileges': 'SeDebugPrivilege, SeSystemtimePrivilege',
            'process_name': 'lsass.exe',
            'mitre_technique': 'T1068'
        }
        events.append(priv_event)
        
        # Account creation (persistence)
        create_time = base_time + timedelta(minutes=15)
        create_event = {
            'timestamp': create_time.isoformat() + 'Z',
            'event_id': '4720',
            'severity': 'critical',
            'source_ip': '10.0.1.100',
            'username': 'intern',
            'hostname': 'WORKSTATION-03',
            'description': 'New user account created by escalated user',
            'new_account': 'backdoor_user',
            'process_name': 'net.exe',
            'mitre_technique': 'T1136.001'
        }
        events.append(create_event)
        
        return events
    
    def generate_malware_execution_scenario(self, base_time):
        """Generate malware execution chain"""
        events = []
        
        # PowerShell execution from Word document
        exec_time = base_time + timedelta(minutes=20)
        exec_event = {
            'timestamp': exec_time.isoformat() + 'Z',
            'event_id': '4688',
            'severity': 'high',
            'source_ip': '10.0.1.50',
            'username': 'msmith',
            'hostname': 'WORKSTATION-02',
            'description': 'PowerShell execution from Microsoft Word',
            'process_name': 'powershell.exe',
            'parent_process': 'winword.exe',
            'command_line': 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden',
            'mitre_technique': 'T1059.001'
        }
        events.append(exec_event)
        
        # Network connection to C2 server
        network_time = base_time + timedelta(minutes=21)
        network_event = {
            'timestamp': network_time.isoformat() + 'Z',
            'event_id': '3',
            'severity': 'high',
            'source_ip': '10.0.1.50',
            'username': 'msmith',
            'hostname': 'WORKSTATION-02',
            'description': 'Outbound connection to suspicious IP',
            'destination_ip': '185.220.100.240',
            'destination_port': '443',
            'process_name': 'powershell.exe',
            'mitre_technique': 'T1071.001'
        }
        events.append(network_event)
        
        # File creation in startup folder
        file_time = base_time + timedelta(minutes=22)
        file_event = {
            'timestamp': file_time.isoformat() + 'Z',
            'event_id': '11',
            'severity': 'high',
            'source_ip': '10.0.1.50',
            'username': 'msmith',
            'hostname': 'WORKSTATION-02',
            'description': 'File created in startup folder for persistence',
            'file_path': 'C:\\Users\\msmith\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe',
            'process_name': 'powershell.exe',
            'mitre_technique': 'T1547.001'
        }
        events.append(file_event)
        
        return events
    
    def generate_normal_activity(self, base_time):
        """Generate normal baseline activity"""
        events = []
        
        # Regular user logons throughout the day
        for i in range(30):
            event_time = base_time + timedelta(minutes=random.randint(0, 480))  # 8 hour workday
            user = random.choice(self.regular_users)
            workstation = random.choice(self.workstations)
            internal_ip = random.choice(self.internal_ips) + str(random.randint(10, 100))
            
            # Mostly successful logons
            if random.random() < 0.9:  # 90% success rate
                event = {
                    'timestamp': event_time.isoformat() + 'Z',
                    'event_id': '4624',
                    'severity': 'low',
                    'source_ip': internal_ip,
                    'username': user,
                    'hostname': workstation,
                    'description': 'Standard user logon',
                    'logon_type': '2',
                    'process_name': 'winlogon.exe',
                    'mitre_technique': 'T1078'
                }
            else:  # Occasional failed logon (typo)
                event = {
                    'timestamp': event_time.isoformat() + 'Z',
                    'event_id': '4625',
                    'severity': 'low',
                    'source_ip': internal_ip,
                    'username': user,
                    'hostname': workstation,
                    'description': 'Failed logon (likely typo)',
                    'failure_reason': '0xC000006A',
                    'logon_type': '2',
                    'process_name': 'winlogon.exe',
                    'mitre_technique': 'T1110'
                }
            
            events.append(event)
            
        return events
    
    def create_sample_events(self):
        """Generate comprehensive security event dataset"""
        base_time = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)
        all_events = []
        
        print("Generating security event scenarios...")
        
        # Generate attack scenarios
        brute_force_events = self.generate_brute_force_scenario(base_time)
        privilege_escalation_events = self.generate_privilege_escalation_scenario(base_time)
        malware_events = self.generate_malware_execution_scenario(base_time)
        normal_events = self.generate_normal_activity(base_time)
        
        # Combine all events
        all_events.extend(brute_force_events)
        all_events.extend(privilege_escalation_events)
        all_events.extend(malware_events)
        all_events.extend(normal_events)
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])
        
        print(f"Generated {len(all_events)} security events:")
        print(f"  - Brute force attack: {len(brute_force_events)} events")
        print(f"  - Privilege escalation: {len(privilege_escalation_events)} events")
        print(f"  - Malware execution: {len(malware_events)} events")
        print(f"  - Normal activity: {len(normal_events)} events")
        
        return all_events
    
    def save_events(self, events, filename="sample-data/combined_security_events.json"):
        """Save events to JSON file"""
        import os
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2, ensure_ascii=False)
        
        print(f"Events saved to {filename}")

if __name__ == "__main__":
    print("SOC Security Event Generator")
    print("=" * 40)
    
    generator = SecurityEventGenerator()
    events = generator.create_sample_events()
    generator.save_events(events)
    
    print(f"\nSample events ready for analysis!")
    print("Run: python scripts/alert_triage.py")
