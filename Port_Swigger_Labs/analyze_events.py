import re
import json
from collections import defaultdict

SUBSCRIBE_LOG = 'subscribe.log'
PUBLISH_LOG = 'publish.log'

def parse_log_file(file_path):
    """Parses a log file to extract event information."""
    event_map = defaultdict(list)
    # Regex to find event names, which are typically strings like "system.shutdown"
    event_regex = re.compile(r'["\']([a-zA-Z0-9_\.]+?)["\']')

    try:
        with open(file_path, 'r') as f:
            for line in f:
                # Extract file path and the rest of the line
                match = re.match(r'([^:]+):(.*)', line)
                if not match:
                    continue
                
                file_name, content = match.groups()
                
                # Find all potential event names in the line
                potential_events = event_regex.findall(content)
                
                for event in potential_events:
                    # Simple filter to avoid false positives
                    if '.' in event and not event.endswith('.'):
                        event_map[event].append(file_name.strip())
                        # We take the first valid event found in the line
                        break

    except FileNotFoundError:
        print(f"Error: {file_path} not found. Please run the grep searches first.")
        return None

    return event_map

def main():
    """Main function to analyze and print the event map."""
    print("Analyzing event subscriptions...")
    subscribers = parse_log_file(SUBSCRIBE_LOG)
    
    print("Analyzing event publications...")
    publishers = parse_log_file(PUBLISH_LOG)

    if subscribers is None or publishers is None:
        print("Could not complete analysis due to missing log files.")
        return

    # Combine the data into a single structure
    all_events = defaultdict(lambda: {'publishers': [], 'subscribers': []})

    for event, files in publishers.items():
        all_events[event]['publishers'] = sorted(list(set(files)))

    for event, files in subscribers.items():
        all_events[event]['subscribers'] = sorted(list(set(files)))

    # Save the results to a JSON file
    output_filename = 'event_map.json'
    with open(output_filename, 'w') as f:
        json.dump(all_events, f, indent=4, sort_keys=True)

    print(f"\nEvent map has been saved to {output_filename}")
    print(f"Found {len(all_events)} unique events.")

if __name__ == "__main__":
    main()
