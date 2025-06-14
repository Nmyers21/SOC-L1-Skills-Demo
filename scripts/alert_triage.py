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
        
        # MITRE ATT&CK technique mappings
        self.mitre_mapping = {
            'brute_force': 'T1110.001',      # Password Guessing
            'privilege_escalation': 'T1068', # Exploitation for Privilege Escalation
            'lateral_movement': 'T1021',     # Remote Services
            'account_creation': 'T1136.001', # Create Local Account
            'credential_access': 'T1110',    # Brute Force
            'persistence': 'T1547.001',     # Registry Run Keys
            'powershell_execution': 'T1059.001', # PowerShell
            'command_control': 'T1071.001'   # Web Protocols
        }
        
        # Expanded Windows Event ID mappings with MITRE techniques
        self.event_scores = {
            '4625': {'score': 3, 'description': 'Failed authentication attempt', 'mitre': 'T1110.001'},
            '4624': {'score': 1, 'description': 'Successful logon', 'mitre': 'T1078'},
            '4672': {'score': 5, 'description': 'Special privileges assigned', 'mitre': 'T1068'},
            '4648': {'score': 3, 'description': 'Explicit credential use', 'mitre': 'T1078'},
            '4720': {'score': 6, 'description': 'User account created', 'mitre': 'T1136.001'},
            '4688': {'score': 2, 'description': 'Process creation', 'mitre': 'T1059'},
            '4732': {'score': 4, 'description': 'Member added to security group', 'mitre': 'T1098'},
            '3': {'score': 3, 'description': 'Network connection (Sysmon)', 'mitre': 'T1071.001'},
            '11': {'score': 2, 'description': 'File creation (Sysmon)', 'mitre': 'T1105'}
        }
        
        # Known suspicious IP ranges for testing
        self.suspicious_ranges = ['203.0.113.', '198.51.100.', '185.220.100.']
        
        logger.info("Alert triage engine initialized with incident reporting")
    
    def generate_incident_report(self, alert, risk_score, analysis_notes, priority):
        """Generate professional incident report for SOC documentation"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        report = {
            'incident_metadata': {
                'incident_id': incident_id,
                'created_at': datetime.now().isoformat(),
                'analyst': 'SOC L1 Analyst',
                'priority': priority,
                'risk_score': f"{risk_score}/20",
                'status': 'OPEN',
                'classification': self.classify_incident(alert, analysis_notes)
            },
            
            'alert_details': {
                'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                'event_id': alert.get('event_id', ''),
                'source_ip': alert.get('source_ip', ''),
                'username': alert.get('username', ''),
                'hostname': alert.get('hostname', ''),
                'description': alert.get('description', 'Security event detected')
            },
            
            'technical_analysis': {
                'findings': analysis_notes,
                'threat_indicators': self.extract_iocs(alert),
                'mitre_techniques': self.get_mitre_techniques(alert),
                'affected_systems': [alert.get('hostname', 'Unknown')],
                'attack_stage': self.determine_attack_stage(alert)
            },
            
            'escalation_criteria': {
                'escalate_to_l2': priority in ['CRITICAL', 'HIGH'],
                'escalation_reason': f"Priority {priority} incident requires L2 analysis",
                'sla_response_time': self.get_sla_time(priority),
                'notification_required': priority == 'CRITICAL'
            },
            
            'recommended_actions': self.get_recommended_actions(priority, analysis_notes),
            
            'investigation_notes': (
                f"SOC L1 triage completed. Risk assessment: {risk_score}/20 points. "
                f"Priority classification: {priority}. "
                f"{'Escalation required.' if priority in ['CRITICAL', 'HIGH'] else 'Standard monitoring.'}"
            )
        }
        
        return report
    
    def classify_incident(self, alert, notes):
        """Classify incident type based on analysis"""
        event_id = alert.get('event_id', '')
        
        if event_id == '4625' or any('failed' in note.lower() for note in notes):
            return 'Brute Force Attack'
        elif event_id == '4672' or any('privilege' in note.lower() for note in notes):
            return 'Privilege Escalation'
        elif event_id == '4720':
            return 'Account Creation'
        elif any('external ip' in note.lower() for note in notes):
            return 'External Access Attempt'
        else:
            return 'Security Event'
    
    def extract_iocs(self, alert):
        """Extract Indicators of Compromise from alert"""
        iocs = []
        
        # IP addresses
        source_ip = alert.get('source_ip', '')
        if source_ip and not self.is_internal_ip(source_ip):
            iocs.append(f"IP: {source_ip}")
            
        # Usernames
        username = alert.get('username', '')
        if username and any(admin in username.lower() for admin in self.admin_accounts):
            iocs.append(f"Admin Account: {username}")
            
        # Hostnames
        hostname = alert.get('hostname', '')
        if hostname:
            iocs.append(f"Host: {hostname}")
            
        # Process names
        process_name = alert.get('process_name', '')
        if process_name:
            iocs.append(f"Process: {process_name}")
            
        return iocs
    
    def determine_attack_stage(self, alert):
        """Determine attack stage based on MITRE technique"""
        event_id = alert.get('event_id', '')
        
        if event_id == '4625':
            return 'Initial Access'
        elif event_id == '4672':
            return 'Privilege Escalation'
        elif event_id == '4720':
            return 'Persistence'
        elif event_id == '4624':
            return 'Lateral Movement'
        else:
            return 'Unknown'
    
    def get_sla_time(self, priority):
        """Get SLA response time based on priority"""
        sla_times = {
            'CRITICAL': '15 minutes',
            'HIGH': '30 minutes',
            'MEDIUM': '2 hours',
            'LOW': '8 hours'
        }
        return sla_times.get(priority, '8 hours')
    
    def get_recommended_actions(self, priority, notes):
        """Generate response recommendations based on analysis"""
        actions = []
        
        if priority == 'CRITICAL':
            actions.extend([
                "Escalate to SOC L2 within 15 minutes",
                "Consider system isolation",
                "Notify incident response team",
                "Begin timeline reconstruction"
            ])
        elif priority == 'HIGH':
            actions.extend([
                "Escalate to SOC L2 within 30 minutes",
                "Monitor for additional activity",
                "Document findings in case management",
                "Enhanced monitoring of affected systems"
            ])
        elif priority == 'MEDIUM':
            actions.extend([
                "Continue standard monitoring",
                "Document for trend analysis",
                "Review in next shift briefing"
            ])
        else:
            actions.extend([
                "Log for historical analysis",
                "Include in baseline metrics"
            ])
            
        # Add specific actions based on findings
        if any('external ip' in note.lower() for note in notes):
            actions.append("Review firewall rules for source IP")
            
        if any('admin' in note.lower() for note in notes):
            actions.append("Review admin account usage policies")
            
        return actions
    
    def get_mitre_techniques(self, alert):
        """Extract MITRE ATT&CK techniques for an alert"""
        techniques = []
        
        # Get technique from event ID mapping
        event_id = str(alert.get('event_id', ''))
        if event_id in self.event_scores:
            mitre_technique = self.event_scores[event_id].get('mitre')
            if mitre_technique:
                techniques.append(mitre_technique)
        
        # Add additional techniques based on alert content
        if alert.get('process_name', '').lower() == 'powershell.exe':
            techniques.append(self.mitre_mapping['powershell_execution'])
            
        return list(set(techniques))  # Remove duplicates
    
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
                    'mitre_technique': self.mitre_mapping['brute_force'],
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
                    'mitre_technique': self.mitre_mapping['privilege_escalation'],
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
                    'mitre_technique': self.mitre_mapping['lateral_movement'],
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
            
            # Add MITRE technique info
            if 'mitre' in event_info:
                analysis['notes'].append(f"MITRE ATT&CK: {event_info['mitre']}")
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
        
        # Add MITRE techniques
        techniques = self.get_mitre_techniques(alert)
        if techniques:
            analysis_notes.append(f"MITRE techniques: {', '.join(techniques)}")
        
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
    
    # Test incident report generation
    test_alert = {
        'event_id': '4625',
        'username': 'administrator',
        'source_ip': '203.0.113.45',
        'hostname': 'WORKSTATION-01',
        'timestamp': datetime.now().isoformat(),
        'description': 'Failed authentication attempt'
    }
    
    print("Incident Report Generation Test:")
    print("=" * 40)
    
    score, notes = engine.analyze_alert(test_alert)
    priority = engine.get_priority(score)
    
    incident_report = engine.generate_incident_report(test_alert, score, notes, priority)
    
    print(f"Incident ID: {incident_report['incident_metadata']['incident_id']}")
    print(f"Priority: {incident_report['incident_metadata']['priority']}")
    print(f"Risk Score: {incident_report['incident_metadata']['risk_score']}")
    print(f"Classification: {incident_report['incident_metadata']['classification']}")
    print(f"SLA Response: {incident_report['escalation_criteria']['sla_response_time']}")
    print(f"Escalate to L2: {incident_report['escalation_criteria']['escalate_to_l2']}")
    
    print(f"\nTechnical Analysis:")
    for finding in incident_report['technical_analysis']['findings']:
        print(f"  - {finding}")
        
    print(f"\nRecommended Actions:")
    for action in incident_report['recommended_actions']:
        print(f"  - {action}")
