#!/usr/bin/env python3
"""
SOC Alert Triage Engine - Basic Implementation
Author: Noah Myers
"""
import json
import logging
import re
from datetime import datetime, timedelta
from collections import defaultdict

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AlertTriageEngine:
    def __init__(self):
        self.risk_thresholds = {
            "low": 3, 
            "medium": 7, 
            "high": 12,
            "critical": 15
        }
        self.admin_accounts = ['admin', 'administrator', 'root', 'sa', 'sysadmin']
        self.service_accounts = ['svc_', 'service_', 'sa_', 'srv_']
        self.guest_accounts = ['guest', 'anonymous', 'temp']
        
        # Correlation thresholds
        self.failed_logon_threshold = 5
        self.time_window_minutes = 10
        
        # Expanded Windows Event ID mappings
        self.event_scores = {
            '4625': {'score': 3, 'description': 'Failed authentication attempt'},
            '4624': {'score': 1, 'description': 'Successful logon'},
            '4672': {'score': 5, 'description': 'Special privileges assigned'},
            '4648': {'score': 3, 'description': 'Explicit credential use'},
            '4720': {'score': 6, 'description': 'User account created'},
            '4688': {'score': 2, 'description': 'Process creation'},
            '4732': {'score': 4, 'description': 'Member added to security group'},
            '3': {'score': 3, 'description': 'Network connection (Sysmon)'},
            '11': {'score': 2, 'description': 'File creation (Sysmon)'}
        }
        
        # Known suspicious IP ranges for testing
        self.suspicious_ranges = ['203.0.113.', '198.51.100.', '185.220.100.']
        
        logger.info("Alert triage engine initialized with correlation analysis")
    
    def correlate_alerts(self, alerts):
        """Perform correlation analysis across multiple alerts"""
        correlations = {
            'brute_force_attacks': [],
            'privilege_escalation_chains': [],
            'lateral_movement': []
        }
        
        # Group alerts for correlation
        ip_events = defaultdict(list)
        user_events = defaultdict(list)
        
        for alert in alerts:
            if alert.get('source_ip'):
                ip_events[alert['source_ip']].append(alert)
            if alert.get('username'):
                user_events[alert['username']].append(alert)
        
        # Detect brute force attacks
        correlations['brute_force_attacks'] = self.detect_brute_force(ip_events)
        
        # Detect privilege escalation chains
        correlations['privilege_escalation_chains'] = self.detect_privilege_escalation(alerts)
        
        # Detect lateral movement
        correlations['lateral_movement'] = self.detect_lateral_movement(user_events)
        
        return correlations
    
    def detect_brute_force(self, ip_events):
        """Detect brute force attack patterns"""
        attacks = []
        
        for ip, events in ip_events.items():
            failed_logons = [e for e in events if e.get('event_id') == '4625']
            
            if len(failed_logons) >= self.failed_logon_threshold:
                targeted_accounts = list(set(e.get('username', '') for e in failed_logons))
                
                attacks.append({
                    'attack_type': 'brute_force',
                    'source_ip': ip,
                    'failed_attempts': len(failed_logons),
                    'targeted_accounts': targeted_accounts,
                    'severity': 'HIGH' if len(failed_logons) >= 10 else 'MEDIUM'
                })
                
        return attacks
    
    def detect_privilege_escalation(self, alerts):
        """Detect privilege escalation chains"""
        escalations = []
        
        # Look for privilege assignment events
        priv_events = [a for a in alerts if a.get('event_id') == '4672']
        
        for priv_event in priv_events:
            # Check if user had other activity before privilege assignment
            username = priv_event.get('username', '')
            related_events = [
                a for a in alerts 
                if a.get('username') == username and a != priv_event
            ]
            
            if related_events:
                escalations.append({
                    'attack_type': 'privilege_escalation',
                    'username': username,
                    'hostname': priv_event.get('hostname', ''),
                    'related_events': len(related_events),
                    'severity': 'CRITICAL'
                })
                
        return escalations
    
    def detect_lateral_movement(self, user_events):
        """Detect lateral movement patterns"""
        movements = []
        
        for user, events in user_events.items():
            # Look for successful logons across multiple hosts
            successful_logons = [e for e in events if e.get('event_id') == '4624']
            unique_hosts = set(e.get('hostname', '') for e in successful_logons if e.get('hostname'))
            
            if len(unique_hosts) > 2:  # User on 3+ different systems
                movements.append({
                    'attack_type': 'lateral_movement',
                    'username': user,
                    'host_count': len(unique_hosts),
                    'hosts': list(unique_hosts),
                    'severity': 'HIGH'
                })
                
        return movements
    
    def is_internal_ip(self, ip):
        """Check if IP address is in internal ranges"""
        if not ip:
            return False
            
        internal_patterns = [
            r'^192\.168\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^127\.',
            r'^169\.254\.'
        ]
        
        return any(re.match(pattern, ip) for pattern in internal_patterns)
    
    def analyze_account(self, alert):
        """Analyze user account for risk factors"""
        username = alert.get('username', '').lower()
        analysis = {'score': 0, 'notes': []}
        
        if not username:
            return analysis
            
        # Administrative account analysis
        if any(admin in username for admin in self.admin_accounts):
            analysis['score'] += 4
            analysis['notes'].append(f"Administrative account targeted: {alert.get('username')}")
            
        # Service account patterns
        elif any(username.startswith(svc) for svc in self.service_accounts):
            analysis['score'] += 3
            analysis['notes'].append(f"Service account activity: {alert.get('username')}")
            
        # Guest/anonymous accounts
        elif username in self.guest_accounts:
            analysis['score'] += 3
            analysis['notes'].append(f"Guest/anonymous account activity: {alert.get('username')}")
            
        # Check for suspicious account patterns
        elif len(username) <= 3:
            analysis['score'] += 2
            analysis['notes'].append(f"Short username pattern: {alert.get('username')}")
            
        # Domain admin patterns (simplified)
        elif 'domain' in username or 'enterprise' in username:
            analysis['score'] += 5
            analysis['notes'].append(f"Domain-level account: {alert.get('username')}")
            
        else:
            analysis['notes'].append(f"Standard user account: {alert.get('username')}")
            
        return analysis
    
    def analyze_source_ip(self, alert):
        """Analyze source IP address for threat indicators"""
        source_ip = alert.get('source_ip', '')
        analysis = {'score': 0, 'notes': []}
        
        if not source_ip:
            return analysis
            
        # External IP check
        if not self.is_internal_ip(source_ip):
            analysis['score'] += 4
            analysis['notes'].append(f"External IP source: {source_ip}")
            
        # Check for known suspicious ranges
        if any(source_ip.startswith(range_) for range_ in self.suspicious_ranges):
            analysis['score'] += 3
            analysis['notes'].append(f"IP in suspicious range: {source_ip}")
            
        # Internal IP gets lower risk
        if self.is_internal_ip(source_ip):
            analysis['notes'].append(f"Internal IP source: {source_ip}")
            
        return analysis
    
    def analyze_event_id(self, alert):
        """Analyze Windows Event ID for risk assessment"""
        event_id = str(alert.get('event_id', ''))
        analysis = {'score': 0, 'notes': []}
        
        if event_id in self.event_scores:
            event_info = self.event_scores[event_id]
            analysis['score'] = event_info['score']
            analysis['notes'].append(f"Event ID {event_id}: {event_info['description']}")
        else:
            analysis['notes'].append(f"Unknown Event ID: {event_id}")
            
        return analysis
    
    def analyze_alert(self, alert):
        """Enhanced risk scoring for security alerts"""
        risk_score = 0
        analysis_notes = []
        
        # Event ID analysis
        event_analysis = self.analyze_event_id(alert)
        risk_score += event_analysis['score']
        analysis_notes.extend(event_analysis['notes'])
        
        # IP address analysis
        ip_analysis = self.analyze_source_ip(alert)
        risk_score += ip_analysis['score']
        analysis_notes.extend(ip_analysis['notes'])
        
        # Account analysis
        account_analysis = self.analyze_account(alert)
        risk_score += account_analysis['score']
        analysis_notes.extend(account_analysis['notes'])
        
        return risk_score, analysis_notes
    
    def get_priority(self, risk_score):
        """Convert risk score to priority level"""
        if risk_score >= self.risk_thresholds['critical']:
            return 'CRITICAL'
        elif risk_score >= self.risk_thresholds['high']:
            return 'HIGH'
        elif risk_score >= self.risk_thresholds['medium']:
            return 'MEDIUM'
        else:
            return 'LOW'

if __name__ == "__main__":
    engine = AlertTriageEngine()
    
    # Test correlation with sample attack scenarios
    test_alerts = [
        # Brute force scenario
        {'event_id': '4625', 'username': 'admin', 'source_ip': '203.0.113.45', 'hostname': 'WS01'},
        {'event_id': '4625', 'username': 'administrator', 'source_ip': '203.0.113.45', 'hostname': 'WS01'},
        {'event_id': '4625', 'username': 'admin', 'source_ip': '203.0.113.45', 'hostname': 'WS01'},
        {'event_id': '4625', 'username': 'admin', 'source_ip': '203.0.113.45', 'hostname': 'WS01'},
        {'event_id': '4625', 'username': 'admin', 'source_ip': '203.0.113.45', 'hostname': 'WS01'},
        {'event_id': '4625', 'username': 'admin', 'source_ip': '203.0.113.45', 'hostname': 'WS01'},
        
        # Privilege escalation scenario
        {'event_id': '4624', 'username': 'jdoe', 'source_ip': '10.0.1.100', 'hostname': 'WS02'},
        {'event_id': '4672', 'username': 'jdoe', 'source_ip': '10.0.1.100', 'hostname': 'WS02'},
        
        # Lateral movement scenario
        {'event_id': '4624', 'username': 'bwilson', 'source_ip': '10.0.1.50', 'hostname': 'WS03'},
        {'event_id': '4624', 'username': 'bwilson', 'source_ip': '10.0.1.50', 'hostname': 'WS04'},
        {'event_id': '4624', 'username': 'bwilson', 'source_ip': '10.0.1.50', 'hostname': 'WS05'}
    ]
    
    print("Correlation Analysis Results:")
    print("=" * 40)
    
    correlations = engine.correlate_alerts(test_alerts)
    
    for attack_type, attacks in correlations.items():
        if attacks:
            print(f"{attack_type.replace('_', ' ').title()}:")
            for attack in attacks:
                print(f"  - {attack}")
            print()
