import nmap
import yaml
import logging
import requests
from time import sleep


# Configure logging
logging.basicConfig(
    filename="port_scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def load_config(config_file):
    """Load the YAML configuration file."""
    with open(config_file, 'r') as file:
        return yaml.safe_load(file)


def send_slack_notification(webhook_url, message):
    """Send a notification to a Slack channel."""
    try:
        payload = {"text": message}
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            logging.info("Slack notification sent.")
        else:
            logging.error(f"Failed to send Slack notification: {response.text}")
    except Exception as e:
        logging.error(f"Error sending Slack notification: {e}")


def scan_target(nm, target, whitelisted_ports):
    """Scan the target for open ports and return unwhitelisted open ports."""
    try:
        nm.scan(hosts=target, arguments="-T4 -sT --open")  # TCP connect scan
        open_ports = []
        
        # Ensure we check all hosts returned by the scanner
        for host in nm.all_hosts():
            logging.info(f"Scanned host: {host} ({nm[host].hostname()})")
            
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    if port not in whitelisted_ports:
                        open_ports.append((port, nm[host]['tcp'][port]['state']))
        return open_ports
    except Exception as e:
        logging.error(f"Error scanning {target}: {e}")
        return []

def main():
    config = load_config("config.yaml")
    nm = nmap.PortScanner()
    slack_webhook = config['slack_webhook']
    logging.info("Port Scanner Service started.")

    while True:
        for target in config['targets']:
            address = target['address']
            whitelisted_ports = target.get('whitelisted_ports', [])
            try:
                print(f"Scanning {address}...")
                open_ports = scan_target(nm, address, whitelisted_ports)

                if open_ports:
                    # Log and prepare detailed Slack message
                    for port, state in open_ports:
                        logging.warning(f"Threat detected: {address} - Port {port}: {state}")

                    message = f"<!channel>, *Open ports detected* on {address}:\n"
                    message += "\n".join([f" - Port {port}: {state}" for port, state in open_ports])
                    send_slack_notification(slack_webhook, message)

            except Exception as e:
                logging.error(f"Error scanning {address}: {e}")
        sleep(config.get('scan_interval', 60))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Port Scanner Service stopped by user.")
        print("Service stopped.")
