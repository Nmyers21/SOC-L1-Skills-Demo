#!/usr/bin/env python3
"""
SOC L1 Alert Triage - Main Analysis Workflow
Comprehensive security event analysis and incident generation
Author: Noah Myers
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

# Add scripts directory to path for imports
sys.path.append(str(Path(__file__).parent))

try:
    from alert_triage import AlertTriageEngine
except ImportError:
    print("Error: Could not import alert_triage module")
    print("Make sure alert_triage.py is in the scripts directory")
    sys.exit(1)

class SOCAnalysisWorkflow:
    def __init__(self):
        self.triage_engine = AlertTriageEngine()
        self.data_file = "sample-data/combined_security_events.json"
        self.results = {
            'analysis_metadata': {},
            'incidents_created': [],
            'correlations': {},
            'priority_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'threat_summary': {
                'external_ips': set(),
                'admin_accounts': set(),
                'mitre_techniques': set()
            }
        }
        
    def load_security_events(self):
        """Load security events from data file"""
        if not os.path.exists(self.data_file):
            print(f"Error: Data file not found: {self.data_file}")
            print("Run: python scripts/generate_sample_data.py")
            return None
            
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                events = json.load(f)
            print(f"Loaded {len(events)} security events from {self.data_file}")
            return events
        except Exception as e:
            print(f"Error loading events: {e}")
            return None
    
    def process_individual_alerts(self, events):
        """Process each alert individually for triage"""
        print("\nProcessing individual alerts...")
        
        for event in events:
            try:
                # Analyze each alert
                risk_score, analysis_notes = self.triage_engine.analyze_alert(event)
                priority = self.triage_engine.get_priority(risk_score)
                
                # Update summary counts
                self.results['priority_summary'][priority.lower()] += 1
                
                # Track threat indicators
                if event.get('source_ip') and not self.triage_engine.is_internal_ip(event['source_ip']):
                    self.results['threat_summary']['external_ips'].add(event['source_ip'])
                    
                username = event.get('username', '').lower()
                if any(admin in username for admin in self.triage_engine.admin_accounts):
                    self.results['threat_summary']['admin_accounts'].add(event['username'])
                    
                mitre_techniques = self.triage_engine.get_mitre_techniques(event)
                self.results['threat_summary']['mitre_techniques'].update(mitre_techniques)
                
                # Create incident reports for HIGH and CRITICAL alerts
                if priority in ['HIGH', 'CRITICAL']:
                    incident_report = self.triage_engine.generate_incident_report(
                        event, risk_score, analysis_notes, priority
                    )
                    self.results['incidents_created'].append(incident_report)
                    
            except Exception as e:
                print(f"Error processing alert: {e}")
                continue
    
    def perform_correlation_analysis(self, events):
        """Perform cross-event correlation analysis"""
        print("Performing correlation analysis...")
        
        try:
            correlations = self.triage_engine.correlate_alerts(events)
            self.results['correlations'] = correlations
            
            # Count correlation findings
            correlation_count = sum(len(attacks) for attacks in correlations.values())
            print(f"Found {correlation_count} correlation patterns")
            
        except Exception as e:
            print(f"Error in correlation analysis: {e}")
    
    def generate_analysis_summary(self):
        """Generate comprehensive analysis summary"""
        metadata = {
            'analysis_time': datetime.now().isoformat(),
            'analyst': 'SOC L1 Analyst',
            'events_processed': sum(self.results['priority_summary'].values()),
            'incidents_created': len(self.results['incidents_created']),
            'data_source': self.data_file
        }
        self.results['analysis_metadata'] = metadata
        
        # Convert sets to lists for JSON serialization
        for key, value in self.results['threat_summary'].items():
            if isinstance(value, set):
                self.results['threat_summary'][key] = list(value)
    
    def display_results(self):
        """Display analysis results to console"""
        print("\n" + "=" * 50)
        print("SOC L1 ALERT TRIAGE ANALYSIS RESULTS")
        print("=" * 50)
        
        metadata = self.results['analysis_metadata']
        print(f"Events Processed: {metadata['events_processed']}")
        print(f"Incidents Created: {metadata['incidents_created']}")
        print(f"Analysis Time: {metadata['analysis_time']}")
        
        print(f"\nPriority Distribution:")
        summary = self.results['priority_summary']
        print(f"  Critical: {summary['critical']}")
        print(f"  High: {summary['high']}")
        print(f"  Medium: {summary['medium']}")
        print(f"  Low: {summary['low']}")
        
        # Show threat indicators
        threat_summary = self.results['threat_summary']
        if threat_summary['external_ips']:
            print(f"\nExternal IPs Detected:")
            for ip in threat_summary['external_ips']:
                print(f"  - {ip}")
                
        if threat_summary['admin_accounts']:
            print(f"\nAdmin Accounts Involved:")
            for account in threat_summary['admin_accounts']:
                print(f"  - {account}")
                
        if threat_summary['mitre_techniques']:
            print(f"\nMITRE ATT&CK Techniques:")
            for technique in threat_summary['mitre_techniques']:
                print(f"  - {technique}")
        
        # Show correlation findings
        correlations = self.results['correlations']
        
        if correlations.get('brute_force_attacks'):
            print(f"\nBRUTE FORCE ATTACKS DETECTED:")
            for attack in correlations['brute_force_attacks']:
                print(f"  Source: {attack['source_ip']}")
                print(f"  Attempts: {attack['failed_attempts']}")
                print(f"  Targets: {', '.join(attack['targeted_accounts'])}")
                print(f"  MITRE: {attack['mitre_technique']}")
                print()
                
        if correlations.get('privilege_escalation_chains'):
            print(f"PRIVILEGE ESCALATION DETECTED:")
            for escalation in correlations['privilege_escalation_chains']:
                print(f"  User: {escalation['username']}")
                print(f"  Host: {escalation['hostname']}")
                print(f"  Related Events: {escalation['related_events']}")
                print(f"  MITRE: {escalation['mitre_technique']}")
                print()
                
        if correlations.get('lateral_movement'):
            print(f"LATERAL MOVEMENT DETECTED:")
            for movement in correlations['lateral_movement']:
                print(f"  User: {movement['username']}")
                print(f"  Host Count: {movement['host_count']}")
                print(f"  Hosts: {', '.join(movement['hosts'])}")
                print(f"  MITRE: {movement['mitre_technique']}")
                print()
        
        # Show sample incident report
        if self.results['incidents_created']:
            print(f"SAMPLE INCIDENT REPORT")
            print("-" * 30)
            incident = self.results['incidents_created'][0]
            metadata = incident['incident_metadata']
            details = incident['alert_details']
            analysis = incident['technical_analysis']
            
            print(f"Incident ID: {metadata['incident_id']}")
            print(f"Priority: {metadata['priority']}")
            print(f"Risk Score: {metadata['risk_score']}")
            print(f"Classification: {metadata['classification']}")
            print(f"Event Time: {details['timestamp']}")
            print(f"Source IP: {details['source_ip']}")
            print(f"Username: {details['username']}")
            print(f"Hostname: {details['hostname']}")
            
            print(f"\nKey Findings:")
            for finding in analysis['findings'][:3]:
                print(f"  - {finding}")
                
            if analysis['threat_indicators']:
                print(f"\nThreat Indicators:")
                for ioc in analysis['threat_indicators']:
                    print(f"  - {ioc}")
                    
            escalation = incident['escalation_criteria']
            print(f"\nEscalation Required: {'Yes' if escalation['escalate_to_l2'] else 'No'}")
            print(f"SLA Response Time: {escalation['sla_response_time']}")
    
    def save_results(self):
        """Save analysis results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f"analysis_results_{timestamp}.json"
        
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
            print(f"\nResults saved to: {results_file}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def run_analysis(self):
        """Main analysis workflow execution"""
        print("SOC L1 Alert Triage Engine")
        print("Starting comprehensive security analysis...")
        
        # Load events
        events = self.load_security_events()
        if not events:
            return False
            
        # Process individual alerts
        self.process_individual_alerts(events)
        
        # Perform correlation analysis
        self.perform_correlation_analysis(events)
        
        # Generate summary
        self.generate_analysis_summary()
        
        # Display results
        self.display_results()
        
        # Save results
        self.save_results()
        
        print(f"\nAnalysis completed successfully!")
        print(f"Ready for L2 escalation and investigation")
        
        return True

def main():
    """Main entry point"""
    try:
        workflow = SOCAnalysisWorkflow()
        success = workflow.run_analysis()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        print(f"Analysis failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
