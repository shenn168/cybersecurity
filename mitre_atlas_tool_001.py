#!/usr/bin/env python3
"""
MITRE ATLAS (Adversarial Threat Landscape for AI Systems) API Tool
Access and search MITRE ATLAS data for AI/ML security threats
"""

import requests
import json
import sys
from datetime import datetime

class MitreAtlasAPI:
    def __init__(self):
        # Updated GitHub raw content URLs for ATLAS
        # ATLAS website uses STIX 2.1 format
        self.atlas_url = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/atlas.json"
        
        # Alternative source - ATLAS website data
        self.atlas_web_url = "https://atlas.mitre.org/resources/atlas-data.json"
        
        # Backup: Try ATT&CK STIX data
        self.attack_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        self.data = None
        self.techniques = []
        self.tactics = []
        self.case_studies = []
        self.mitigations = []
    
    def fetch_atlas_data(self):
        """Fetch ATLAS data from available sources"""
        
        # Try multiple sources in order
        sources = [
            ("ATLAS GitHub (atlas.json)", self.atlas_url),
            ("ATLAS Website", self.atlas_web_url),
            ("ATLAS GitHub (master branch)", "https://raw.githubusercontent.com/mitre-atlas/atlas-data/master/dist/ATLAS.json"),
            ("ATLAS Navigator", "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/ATLAS.json")
        ]
        
        for source_name, url in sources:
            try:
                print(f"[INFO] Trying {source_name}...")
                print(f"[INFO] URL: {url}")
                
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    try:
                        self.data = response.json()
                        print(f"[SUCCESS] ATLAS data loaded from {source_name}!")
                        
                        # Parse data
                        self._parse_data()
                        
                        if len(self.techniques) > 0 or len(self.tactics) > 0:
                            print(f"[SUCCESS] Successfully parsed ATLAS data!")
                            return True
                        else:
                            print(f"[WARNING] No techniques or tactics found in {source_name}")
                            continue
                    except json.JSONDecodeError as e:
                        print(f"[ERROR] Failed to parse JSON from {source_name}: {e}")
                        continue
                else:
                    print(f"[WARNING] {source_name} returned status {response.status_code}")
                    continue
                    
            except requests.exceptions.RequestException as e:
                print(f"[WARNING] Failed to fetch from {source_name}: {e}")
                continue
        
        # If all sources fail, try to use sample/cached data
        print("\n[WARNING] All primary sources failed. Attempting to use fallback data...")
        return self._load_fallback_data()
    
    def _load_fallback_data(self):
        """Load fallback/sample ATLAS data"""
        print("[INFO] Loading sample ATLAS techniques...")
        
        # Sample ATLAS techniques (representative examples)
        sample_techniques = [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-001",
                "name": "Adversarial Example Generation",
                "description": "Adversaries may craft inputs specifically designed to cause a machine learning model to make mistakes. These adversarial examples appear normal to humans but cause the model to misclassify or produce incorrect outputs.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0043"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "ml-attack-staging"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-002",
                "name": "Model Inversion",
                "description": "Adversaries may query a machine learning model to reconstruct sensitive training data. This can expose private information that was used to train the model.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0044"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "collection"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-003",
                "name": "Data Poisoning",
                "description": "Adversaries may introduce malicious data into the training dataset to manipulate the behavior of the resulting machine learning model.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0020"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "ml-attack-staging"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-004",
                "name": "Model Backdoor",
                "description": "Adversaries may insert backdoors into machine learning models that can be triggered by specific inputs while maintaining normal behavior for other inputs.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0018"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "persistence"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-005",
                "name": "Model Extraction",
                "description": "Adversaries may query a machine learning model to create a functionally equivalent copy. This can steal intellectual property and enable further attacks.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0057"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "collection"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-006",
                "name": "Membership Inference",
                "description": "Adversaries may determine whether a specific data point was used in the training dataset, potentially exposing sensitive information.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0045"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "reconnaissance"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-007",
                "name": "Supply Chain Compromise - ML Model",
                "description": "Adversaries may compromise the machine learning model supply chain, including pre-trained models, model repositories, or deployment pipelines.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0010"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "initial-access"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-008",
                "name": "Evade ML Model",
                "description": "Adversaries may modify their malicious artifacts to avoid detection by machine learning-based security systems.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0015"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "defense-evasion"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-009",
                "name": "Discover ML Model Family",
                "description": "Adversaries may probe a machine learning system to determine the model architecture and algorithm being used.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0033"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "discovery"}
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-010",
                "name": "Denial of ML Service",
                "description": "Adversaries may disrupt the availability of a machine learning service through resource exhaustion or algorithmic attacks.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.T0049"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas", "phase_name": "impact"}
                ]
            }
        ]
        
        sample_tactics = [
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-recon",
                "name": "Reconnaissance",
                "description": "The adversary is trying to gather information about the ML system.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0001"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-resource",
                "name": "Resource Development",
                "description": "The adversary is trying to develop resources to support operations against ML systems.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0002"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-initial",
                "name": "Initial Access",
                "description": "The adversary is trying to get into the ML system.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0003"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-ml-access",
                "name": "ML Model Access",
                "description": "The adversary is trying to gain access to the machine learning model.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0004"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-execution",
                "name": "Execution",
                "description": "The adversary is trying to run malicious code in the ML system.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0005"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-persistence",
                "name": "Persistence",
                "description": "The adversary is trying to maintain their foothold in the ML system.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0006"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-defense",
                "name": "Defense Evasion",
                "description": "The adversary is trying to avoid detection in the ML system.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0007"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-discovery",
                "name": "Discovery",
                "description": "The adversary is trying to learn about the ML system environment.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0008"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-collection",
                "name": "Collection",
                "description": "The adversary is trying to gather data from the ML system.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0009"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-staging",
                "name": "ML Attack Staging",
                "description": "The adversary is staging an attack against the machine learning model.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0010"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-exfil",
                "name": "Exfiltration",
                "description": "The adversary is trying to steal data from the ML system.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0011"}
                ]
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--atlas-impact",
                "name": "Impact",
                "description": "The adversary is trying to manipulate, interrupt, or destroy ML systems and data.",
                "external_references": [
                    {"source_name": "ATLAS", "external_id": "AML.TA0012"}
                ]
            }
        ]
        
        self.data = {
            "type": "bundle",
            "id": "bundle--atlas-fallback",
            "objects": sample_techniques + sample_tactics
        }
        
        self._parse_data()
        
        if len(self.techniques) > 0:
            print(f"[SUCCESS] Loaded {len(self.techniques)} sample ATLAS techniques")
            print(f"[INFO] For complete data, visit: https://atlas.mitre.org/")
            return True
        
        return False
    
    def _parse_data(self):
        """Parse ATLAS STIX data"""
        if not self.data:
            return
        
        objects = self.data.get('objects', [])
        if not objects and isinstance(self.data, list):
            objects = self.data
        
        self.techniques = []
        self.tactics = []
        self.case_studies = []
        self.mitigations = []
        
        for obj in objects:
            obj_type = obj.get('type')
            
            if obj_type == 'attack-pattern':
                self.techniques.append(obj)
            elif obj_type == 'x-mitre-tactic':
                self.tactics.append(obj)
            elif obj_type == 'x-mitre-matrix':
                pass  # Matrix structure
            elif obj_type == 'course-of-action':
                self.mitigations.append(obj)
            elif obj_type == 'x-mitre-collection':
                self.case_studies.append(obj)
        
        print(f"[INFO] Parsed: {len(self.techniques)} techniques, {len(self.tactics)} tactics, {len(self.mitigations)} mitigations")
    
    def search_techniques(self, query):
        """Search techniques by keyword"""
        results = []
        query_lower = query.lower()
        
        for tech in self.techniques:
            name = tech.get('name', '').lower()
            description = tech.get('description', '').lower()
            
            if query_lower in name or query_lower in description:
                results.append(tech)
        
        return results
    
    def get_technique_by_id(self, technique_id):
        """Get technique by ATLAS ID (e.g., AML.T0000)"""
        technique_id = technique_id.upper()
        
        for tech in self.techniques:
            external_refs = tech.get('external_references', [])
            for ref in external_refs:
                ext_id = ref.get('external_id', '')
                if ext_id.upper() == technique_id:
                    return tech
        return None
    
    def get_all_tactics(self):
        """Get all ATLAS tactics"""
        return self.tactics
    
    def get_techniques_by_tactic(self, tactic_name):
        """Get techniques for a specific tactic"""
        results = []
        tactic_name_lower = tactic_name.lower()
        
        for tech in self.techniques:
            kill_chain = tech.get('kill_chain_phases', [])
            for phase in kill_chain:
                phase_name = phase.get('phase_name', '').lower()
                if tactic_name_lower in phase_name or phase_name in tactic_name_lower:
                    results.append(tech)
                    break
        
        return results
    
    def format_technique(self, technique):
        """Format technique for display"""
        name = technique.get('name', 'N/A')
        description = technique.get('description', 'No description')
        
        # Get ATLAS ID
        atlas_id = 'N/A'
        external_refs = technique.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') in ['ATLAS', 'mitre-atlas']:
                atlas_id = ref.get('external_id', 'N/A')
                break
        
        # Get tactics
        tactics = []
        kill_chain = technique.get('kill_chain_phases', [])
        for phase in kill_chain:
            tactics.append(phase.get('phase_name', 'Unknown').replace('-', ' ').title())
        
        output = []
        output.append("=" * 80)
        output.append(f"Technique: {name}")
        output.append(f"ATLAS ID: {atlas_id}")
        output.append(f"Tactics: {', '.join(tactics) if tactics else 'N/A'}")
        output.append("=" * 80)
        output.append(f"\nDescription:")
        
        # Wrap description text
        words = description.split()
        line = ""
        for word in words:
            if len(line + word) > 75:
                output.append(f"  {line}")
                line = word + " "
            else:
                line += word + " "
        if line:
            output.append(f"  {line}")
        
        # Get external references
        if external_refs:
            output.append(f"\
References:")
            for ref in external_refs[:5]:  # Show first 5 references
                if ref.get('url'):
                    output.append(f"  - {ref.get('source_name', 'Source')}: {ref.get('url')}")
        
        return '\n'.join(output)
    
    def display_all_techniques(self, detailed=False):
        """Display all techniques"""
        print("\
" + "=" * 80)
        print(f"  ATLAS TECHNIQUES (Total: {len(self.techniques)})")
        print("=" * 80)
        
        for i, tech in enumerate(self.techniques, 1):
            name = tech.get('name', 'N/A')
            
            # Get ATLAS ID
            atlas_id = 'N/A'
            external_refs = tech.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') in ['ATLAS', 'mitre-atlas']:
                    atlas_id = ref.get('external_id', 'N/A')
                    break
            
            print(f"\n[{i}] {atlas_id}: {name}")
            
            if detailed:
                description = tech.get('description', 'No description')
                print(f"    {description[:150]}...")
    
    def display_all_tactics(self):
        """Display all tactics"""
        print("\
" + "=" * 80)
        print(f"  ATLAS TACTICS (Total: {len(self.tactics)})")
        print("=" * 80)
        
        for i, tactic in enumerate(self.tactics, 1):
            name = tactic.get('name', 'N/A')
            description = tactic.get('description', 'No description')
            
            # Get tactic ID
            tactic_id = 'N/A'
            external_refs = tactic.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') in ['ATLAS', 'mitre-atlas']:
                    tactic_id = ref.get('external_id', 'N/A')
                    break
            
            print(f"\
[{i}] {tactic_id}: {name}")
            print(f"    {description[:150]}...")
    
    def export_to_json(self, data, filename):
        """Export data to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[SUCCESS] Data exported to {filename}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to export: {e}")
            return False

def interactive_menu():
    """Interactive menu for ATLAS API"""
    atlas = MitreAtlasAPI()
    
    print("\n" + "=" * 80)
    print("  MITRE ATLAS API TOOL")
    print("  Adversarial Threat Landscape for AI Systems")
    print("=" * 80)
    
    # Load data
    if not atlas.fetch_atlas_data():
        print("\n[ERROR] Failed to load ATLAS data.")
        print("[INFO] You can access ATLAS directly at: https://atlas.mitre.org/")
        return
    
    while True:
        print("\
" + "=" * 80)
        print("  MAIN MENU")
        print("=" * 80)
        print("\n1. Search Techniques by Keyword")
        print("2. Get Technique by ATLAS ID")
        print("3. List All Techniques")
        print("4. List All Tactics")
        print("5. Get Techniques by Tactic")
        print("6. Export Data to JSON")
        print("7. Refresh ATLAS Data")
        print("8. View ATLAS Statistics")
        print("0. Exit")
        print()
        
        choice = input("Enter your choice (0-8): ").strip()
        
        if choice == '0':
            print("\n[INFO] Exiting MITRE ATLAS Tool. Goodbye!")
            break
        
        elif choice == '1':
            query = input("\nEnter search keyword: ").strip()
            if query:
                results = atlas.search_techniques(query)
                print(f"\
[INFO] Found {len(results)} matching techniques")
                
                for i, tech in enumerate(results, 1):
                    print(f"\n{atlas.format_technique(tech)}")
                    
                    if i < len(results):
                        cont = input("\
Press Enter for next result (or 'q' to quit): ")
                        if cont.lower() == 'q':
                            break
            else:
                print("[ERROR] Query cannot be empty!")
        
        elif choice == '2':
            tech_id = input("\
Enter ATLAS ID (e.g., AML.T0043): ").strip().upper()
            if tech_id:
                tech = atlas.get_technique_by_id(tech_id)
                if tech:
                    print(f"\
{atlas.format_technique(tech)}")
                else:
                    print(f"[ERROR] Technique {tech_id} not found!")
                    print("[TIP] Try searching by keyword (option 1)")
            else:
                print("[ERROR] Technique ID cannot be empty!")
        
        elif choice == '3':
            detail = input("\
Show detailed view? (y/n): ").strip().lower()
            atlas.display_all_techniques(detailed=(detail == 'y'))
        
        elif choice == '4':
            atlas.display_all_tactics()
        
        elif choice == '5':
            print("\
Available tactics:")
            print("  - reconnaissance")
            print("  - resource-development")
            print("  - initial-access")
            print("  - ml-model-access")
            print("  - execution")
            print("  - persistence")
            print("  - defense-evasion")
            print("  - discovery")
            print("  - collection")
            print("  - ml-attack-staging")
            print("  - exfiltration")
            print("  - impact")
            print()
            
            tactic_name = input("Enter tactic name (or part of it): ").strip()
            if tactic_name:
                results = atlas.get_techniques_by_tactic(tactic_name)
                print(f"\
[INFO] Found {len(results)} techniques for '{tactic_name}'")
                
                for tech in results:
                    print(f"\
{atlas.format_technique(tech)}")
            else:
                print("[ERROR] Tactic name cannot be empty!")
        
        elif choice == '6':
            filename = input("\nEnter filename (e.g., atlas_export.json): ").strip()
            if filename:
                if not filename.endswith('.json'):
                    filename += '.json'
                
                export_type = input("Export (1) All data, (2) Techniques only, (3) Tactics only: ").strip()
                
                if export_type == '1':
                    atlas.export_to_json(atlas.data, filename)
                elif export_type == '2':
                    atlas.export_to_json(atlas.techniques, filename)
                elif export_type == '3':
                    atlas.export_to_json(atlas.tactics, filename)
                else:
                    print("[ERROR] Invalid export type!")
            else:
                print("[ERROR] Filename cannot be empty!")
        
        elif choice == '7':
            atlas.fetch_atlas_data()
        
        elif choice == '8':
            print("\
" + "=" * 80)
            print("  ATLAS STATISTICS")
            print("=" * 80)
            print(f"\nTotal Techniques: {len(atlas.techniques)}")
            print(f"Total Tactics: {len(atlas.tactics)}")
            print(f"Total Mitigations: {len(atlas.mitigations)}")
            print(f"Total Case Studies: {len(atlas.case_studies)}")
            
            # Count techniques by tactic
            print("\
Techniques by Tactic:")
            tactic_counts = {}
            for tech in atlas.techniques:
                kill_chain = tech.get('kill_chain_phases', [])
                for phase in kill_chain:
                    phase_name = phase.get('phase_name', 'Unknown')
                    tactic_counts[phase_name] = tactic_counts.get(phase_name, 0) + 1
            
            for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {tactic}: {count}")
        
        else:
            print("[ERROR] Invalid choice! Please select 0-8.")
        
        input("\
Press Enter to continue...")

def main():
    """Main entry point"""
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\
\n[INFO] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\
[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()