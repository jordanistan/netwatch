import os
import json
from datetime import datetime
from netwatch import NetWatch
from simulated_data import generate_simulated_stats, get_risk_assessment
from test_traffic import generate_voip_sample

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def save_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, cls=DateTimeEncoder)

def main():
    # Initialize directories
    base_dir = 'examples'
    captures_dir = os.path.join(base_dir, 'captures')
    reports_dir = os.path.join(base_dir, 'reports')
    logs_dir = os.path.join(base_dir, 'logs')

    for d in [captures_dir, reports_dir, logs_dir]:
        ensure_dir(d)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Generate simulated VoIP traffic
    print("Generating VoIP traffic data...")
    voip_data = generate_voip_sample()
    save_json(voip_data, os.path.join(reports_dir, f'voip_sample_{timestamp}.json'))

    # Generate simulated stats
    print("Generating network statistics...")
    stats_data = generate_simulated_stats()
    save_json(stats_data, os.path.join(reports_dir, f'network_stats_{timestamp}.json'))

    # Generate risk assessment
    print("Generating risk assessment...")
    risk_data = get_risk_assessment()
    save_json(risk_data, os.path.join(reports_dir, f'risk_assessment_{timestamp}.json'))

    # Save VoIP metadata
    print("Saving VoIP metadata...")
    sample_path = os.path.join(reports_dir, f'voip_metadata_{timestamp}.json')
    save_json(voip_data, sample_path)

    print("\nExample files generated:")
    print(f"Reports directory: {reports_dir}")
    print(f"Captures directory: {captures_dir}")
    print(f"Logs directory: {logs_dir}")

if __name__ == '__main__':
    main()
