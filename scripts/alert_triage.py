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
        logger.info("Alert triage engine initialized")
    
    def analyze_alert(self, alert):
        """Basic risk scoring for security alerts"""
        risk_score = 0
        
        # Basic Event ID scoring
        if alert.get('event_id') == '4625':  # Failed logon
            risk_score += 3
        elif alert.get('event_id') == '4672':  # Special privileges
            risk_score += 5
        elif alert.get('event_id') == '4720':  # Account created
            risk_score += 6
            
        # Check for admin accounts
        username = alert.get('username', '').lower()
        if any(admin in username for admin in self.admin_accounts):
            risk_score += 3
            
        return risk_score
    
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
    
    # Test with sample alert
    sample_alert = {
        'event_id': '4625',
        'username': 'admin',
        'source_ip': '10.0.1.100'
    }
    
    score = engine.analyze_alert(sample_alert)
    priority = engine.get_priority(score)
    print(f"Sample alert risk score: {score}")
    print(f"Priority level: {priority}")
