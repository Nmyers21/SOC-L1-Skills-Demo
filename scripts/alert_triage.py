#!/usr/bin/env python3
"""
SOC Alert Triage Engine - Basic Implementation
Author: Noah Myers
"""
import json
import logging
from datetime import datetime

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
        self.admin_accounts = ['admin', 'administrator', 'root']
        
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
        
        logger.info("Alert triage engine initialized with event mappings")
    
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
        
        # Check for admin accounts
        username = alert.get('username', '').lower()
        if any(admin in username for admin in self.admin_accounts):
            risk_score += 3
            analysis_notes.append(f"Administrative account targeted: {alert.get('username')}")
            
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
    
    # Test with multiple sample alerts
    test_alerts = [
        {'event_id': '4625', 'username': 'admin', 'source_ip': '10.0.1.100'},
        {'event_id': '4720', 'username': 'newuser', 'source_ip': '10.0.1.50'},
        {'event_id': '4624', 'username': 'jdoe', 'source_ip': '10.0.1.25'}
    ]
    
    for i, alert in enumerate(test_alerts):
        score, notes = engine.analyze_alert(alert)
        priority = engine.get_priority(score)
        print(f"Alert {i+1}: Score={score}, Priority={priority}")
        for note in notes:
            print(f"  - {note}")
        print()
