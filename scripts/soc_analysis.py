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
import traceback

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
            },
            'performance_metrics': {
                'processing_time': 0,
                'events_per_second': 0,
                'errors_encountered': 0
            }
        }
        
    def print_header(self):
        """Print professional analysis header"""
        print("=" * 60)
        print("SOC L1 ALERT TRIAGE ENGINE")
        print("Comprehensive Security Event Analysis")
        print("=" * 60)
        print(f"Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
    def load_security_events(self):
        """Load security events from data file"""
        print("Loading security events...")
        
        if not os.path.exists(self.data_file):
            print(f"Error: Data file not found: {self.data_file}")
            print("Please run: python scripts/generate_sample_data.py")
            return None
            
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                events = json.load(f)
            print(f"Successfully loaded {len(events)} security events")
            return events
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in data file: {e}")
            return None
        except Exception as e:
            print(f"Error loading events: {e}")
            return None
    
    def process_individual_alerts(self, events):
        """Process each alert individually for triage"""
        print("\nProcessing individual alerts...")
        print("-" * 30)
        
        start_time = datetime.now()
        processed_count = 0
        error_count = 0
        
        for i, event in enumerate(events):
            try:
                # Show progress for every 10 events
                if i % 10 == 0 and i > 0:
                    print(f"Processed {i}/{len(events)} events...")
                
                # Analyze each alert
                risk_score, analysis_notes = self.triage_engine.analyze_alert(event)
                priority = self.triage_engine.get_priority(risk_score)
                
                # Update summary counts
                self.results['priority_summary'][priority.lower()] += 1
                
                # Track threat indicators
                source_ip = event.get('source_ip', '')
                if source_ip and not self.triage_engine.is_internal_ip(source_ip):
                    self.results['threat_summary']['external_ips'].add(source_ip)
                    
                username = event.get('username', '').lower()
                if any(admin in username for admin in self.triage_engine.admin_accounts):
                    self.results['threat_summary']['admin_accounts'].add(event.get('username', ''))
                    
                mitre_techniques = self.triage_engine.get_mitre_techniques(event)
                self.results['threat_summary']['mitre_techniques'].update(mitre_techniques)
                
                # Create incident reports for HIGH and CRITICAL alerts
                if priority in ['HIGH', 'CRITICAL']:
                    try:
                        incident_report = self.triage_engine.generate_incident_report(
                            event, risk_score, analysis_notes, priority
                        )
                        self.results['incidents_created'].append(incident_report)
                        print(f"  -> {priority} priority incident created: {incident_report['incident_metadata']['incident_id']}")
                    except Exception as e:
                        print(f"  -> Error creating incident report: {e}")
                        error_count += 1
                
                processed_count += 1
                
            except Exception as e:
                print(f"Error processing event {i}: {e}")
                error_count += 1
                continue
        
        # Calculate performance metrics
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        events_per_second = processed_count / processing_time if processing_time > 0 else 0
        
        self.results['performance_metrics'] = {
            'processing_time': round(processing_time, 2),
            'events_per_second': round(events_per_second, 2),
            'errors_encountered': error_count,
            'success_rate': round((processed_count / len(events)) * 100, 1) if events else 0
        }
        
        print(f"Completed processing: {processed_count}/{len(events)} events")
        print(f"Processing time: {processing_time:.2f} seconds")
        print(f"Performance: {events_per_second:.2f} events/second")
        if error_count > 0:
            print(f"Errors encountered: {error_count}")
    
    def perform_correlation_analysis(self, events):
        """Perform cross-event correlation analysis"""
        print("\nPerforming correlation analysis...")
        print("-" * 30)
        
        try:
            correlations = self.triage_engine.correlate_alerts(events)
            self.results['correlations'] = correlations
            
            # Count and report correlation findings
            brute_force_count = len(correlations.get('brute_force_attacks', []))
            privilege_esc_count = len(correlations.get('privilege_escalation_chains', []))
            lateral_move_count = len(correlations.get('lateral_movement', []))
            
            total_correlations = brute_force_count + privilege_esc_count + lateral_move_count
            
            print(f"Correlation analysis complete:")
            print(f"  - Brute force attacks: {brute_force_count}")
            print(f"  - Privilege escalations: {privilege_esc_count}")
            print(f"  - Lateral movement: {lateral_move_count}")
            print(f"  - Total attack patterns: {total_correlations}")
            
        except Exception as e:
            print(f"Error in correlation analysis: {e}")
            traceback.print_exc()
    
    def generate_analysis_summary(self):
        """Generate comprehensive analysis summary"""
        metadata = {
            'analysis_time': datetime.now().isoformat(),
            'analyst': 'SOC L1 Analyst',
            'events_processed': sum(self.results['priority_summary'].values()),
            'incidents_created': len(self.results['incidents_created']),
            'data_source': self.data_file,
            'engine_version': '1.0',
            'analysis_duration': self.results['performance_metrics']['processing_time']
        }
        self.results['analysis_metadata'] = metadata
        
        # Convert sets to lists for JSON serialization
        for key, value in self.results['threat_summary'].items():
            if isinstance(value, set):
                self.results['threat_summary'][key] = list(value)
    
    def display_results(self):
        """Display analysis results to console"""
        print("\n" + "=" * 60)
        print("ANALYSIS RESULTS SUMMARY")
        print("=" * 60)
        
        metadata = self.results['analysis_metadata']
        metrics = self.results['performance_metrics']
        
        print(f"Events Processed: {metadata['events_processed']}")
        print(f"Incidents Created: {metadata['incidents_created']}")
        print(f"Analysis Duration: {metadata['analysis_duration']} seconds")
        print(f"Processing Rate: {metrics['events_per_second']} events/second")
        print(f"Success Rate: {metrics['success_rate']}%")
        
        print(f"\nPRIORITY BREAKDOWN:")
        summary = self.results['priority_summary']
        total_events = sum(summary.values())
        for priority, count in summary.items():
            percentage = (count / total_events * 100) if total_events > 0 else 0
            print(f"  {priority.capitalize()}: {count} ({percentage:.1f}%)")
        
        # Show threat indicators
        threat_summary = self.results['threat_summary']
        if threat_summary['external_ips']:
            print(f"\nEXTERNAL IP ADDRESSES:")
            for ip in sorted(threat_summary['external_ips']):
                print(f"  - {ip}")
                
        if threat_summary['admin_accounts']:
            print(f"\nADMIN ACCOUNTS INVOLVED:")
            for account in sorted(threat_summary['admin_accounts']):
                print(f"  - {account}")
                
        if threat_summary['mitre_techniques']:
            print(f"\nMITRE ATT&CK TECHNIQUES:")
            for technique in sorted(threat_summary['mitre_techniques']):
                print(f"  - {technique}")
        
        # Show correlation findings with detailed formatting
        correlations = self.results['correlations']
        
        if correlations.get('brute_force_attacks'):
            print(f"\nBRUTE FORCE ATTACKS DETECTED:")
            print("-" * 35)
            for i, attack in enumerate(correlations['brute_force_attacks'], 1):
                print(f"Attack {i}:")
                print(f"  Source IP: {attack['source_ip']}")
                print(f"  Failed Attempts: {attack['failed_attempts']}")
                print(f"  Target Accounts: {', '.join(attack['targeted_accounts'])}")
                print(f"  MITRE Technique: {attack['mitre_technique']}")
                print(f"  Severity: {attack['severity']}")
                print()
                
        if correlations.get('privilege_escalation_chains'):
            print(f"PRIVILEGE ESCALATION DETECTED:")
            print("-" * 32)
            for i, escalation in enumerate(correlations['privilege_escalation_chains'], 1):
                print(f"Escalation {i}:")
                print(f"  Username: {escalation['username']}")
                print(f"  Hostname: {escalation['hostname']}")
                print(f"  Related Events: {escalation['related_events']}")
                print(f"  MITRE Technique: {escalation['mitre_technique']}")
                print(f"  Severity: {escalation['severity']}")
                print()
                
        if correlations.get('lateral_movement'):
            print(f"LATERAL MOVEMENT DETECTED:")
            print("-" * 26)
            for i, movement in enumerate(correlations['lateral_movement'], 1):
                print(f"Movement {i}:")
                print(f"  Username: {movement['username']}")
                print(f"  Host Count: {movement['host_count']}")
                print(f"  Affected Hosts: {', '.join(movement['hosts'])}")
                print(f"  MITRE Technique: {movement['mitre_technique']}")
                print(f"  Severity: {movement['severity']}")
                print()
        
        # Show sample incident report with improved formatting
        if self.results['incidents_created']:
            print(f"HIGH PRIORITY INCIDENT EXAMPLE:")
            print("-" * 32)
            incident = self.results['incidents_created'][0]
            metadata = incident['incident_metadata']
            details = incident['alert_details']
            analysis = incident['technical_analysis']
            escalation = incident['escalation_criteria']
            
            print(f"Incident ID: {metadata['incident_id']}")
            print(f"Priority: {metadata['priority']}")
            print(f"Risk Score: {metadata['risk_score']}")
            print(f"Classification: {metadata['classification']}")
            print(f"Created: {metadata['created_at']}")
            print()
            print(f"Event Details:")
            print(f"  Event ID: {details['event_id']}")
            print(f"  Source IP: {details['source_ip']}")
            print(f"  Username: {details['username']}")
            print(f"  Hostname: {details['hostname']}")
            print()
            print(f"Technical Analysis:")
            for finding in analysis['findings'][:3]:
                print(f"  - {finding}")
            print()
            print(f"Escalation: {'Required' if escalation['escalate_to_l2'] else 'Not Required'}")
            print(f"SLA Response: {escalation['sla_response_time']}")
    
    def save_results(self):
        """Save analysis results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f"analysis_results_{timestamp}.json"
        
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
            print(f"\nDetailed results saved to: {results_file}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def run_analysis(self):
        """Main analysis workflow execution"""
        self.print_header()
        
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
        
        print(f"\n" + "=" * 60)
        print("ANALYSIS COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("Ready for L2 escalation and investigation")
        
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
        print(f"Critical error during analysis: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())
