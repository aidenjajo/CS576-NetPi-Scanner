"""
Team Members: Aiden Jajo, Diego Lopez, Manuel Jimenez, Romel Aleman
School: San Diego State University
Course: CS576-03 - Computer Networks and Distributed Systems
Project: NetPi-Scanner

Flask web server for NetPi-Scanner web interface.
Provides routes for network scanning, performance testing, packet sniffing,
and report downloading. Includes ARP spoofing for MITM packet capture.
"""

# import libraries and modules
from flask import Flask, render_template, request, jsonify, send_file, request
import socket
import time
import shutil
import csv, os
import sys
from datetime import datetime

# add parent directory to path so custom modules can be imported
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# import custom function modules
import Functions.scan as scan_module
import Functions.peformance as perf_module
import Functions.clear_cache as cache_module
import Functions.sniffer as sniff_module
import Functions.arp_spoof as arp_module

# Initialize Flask application
app = Flask(__name__)

@app.route("/")
def index():
    """Load homepage"""
    return render_template("index.html")
    
# scan pg; load saved devices (GET) and perform network scanning (POST)

@app.route("/scan", methods=["GET", "POST"])
def scan():
    """Handle network scanning page and scan execution"""
    # GET: load saved devices
    if request.method == 'GET':
        try:
            # Load previously saved devices from CSV
            saved = scan_module.load_devices()
        except Exception:
            saved = []
        return render_template("scan.html", devices=saved)
    
    # POST: run network scan
    try:
        # Setup configuration from .config file
        scan_module.setup_config()
        addr = scan_module.config.get('address', '<address>')
        dns = scan_module.config.get('dns', None)
        subnet = scan_module.config.get('subnet', '24')

        # Execute network scan
        devices = scan_module.scan_network(addr, dns, subnet)
        # Save discovered devices to CSV
        scan_module.save_devices(devices)

        # Return number of devices found
        return jsonify(status='ok', devices=len(devices))
    except Exception as e:
        return jsonify(status='error', message=str(e)), 500

# performance pg; Load log (GET) and measure device performance (POST)

@app.route("/performance", methods=["GET", "POST"])
def performance():
    """Handle performance testing page and performance measurement"""
    # GET: load performance CSV if it exists
    if request.method == 'GET':
        perf_rows = []
        perf_file = os.path.join('CSV', 'performance_log.csv')

        if os.path.exists(perf_file):
            try:
                # read the CSV data
                with open(perf_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        perf_rows.append(row)
            except Exception:
                perf_rows = []

        return render_template("performance.html", perf_rows=perf_rows)

    # POST: run performance tests
    try:
        # Load saved devices from CSV
        devices = perf_module.load_devices()
        if not devices:
            return jsonify(status='error', message='No saved devices'), 400

        # Measure performance metrics for all devices
        measured = perf_module.measure_performance(devices)
        # Log results to CSV
        perf_module.log_performance_data(measured)

        return jsonify(status='ok', devices=len(measured))
    except Exception as e:
        return jsonify(status='error', message=str(e)), 500

# reports page
@app.route("/reports")
def reports():
    """Load reports page for viewing/downloading CSV files"""
    return render_template("reports.html")

# sniffer – Load UI (GET), capture packets and perform MITM if needed (POST)

@app.route("/sniffer", methods=["GET", "POST"], endpoint='sniffer')
def webSniff(): 
    """Handle packet sniffer page and packet capture"""
    if request.method == 'GET':
        # load saved devices from CSV
        devices = []
        devices_file = 'CSV/saved_devices.csv'
        if os.path.exists(devices_file):
            try:
                # Read devices for target selection dropdown
                with open(devices_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        devices.append({
                            'ip': row.get('IP', row.get('ip', '')),
                            'hostname': row.get('Hostname', row.get('hostname', row.get('IP', 'Unknown')))
                        })
            except Exception:
                devices = []

        return render_template("sniffer.html", devices=devices)
    
    # POST: begin sniffing
    try:
        # Get capture parameters from form
        duration = int(request.form.get('duration', 10))
        protocol_filter = request.form.get('filter', '')
        target = request.form.get('device', '').strip()

        # generate timestamped capture file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = f"capture_{timestamp}.pcap"

        # get self IP and router IP
        my_ip_addr = get_host_ip()
        gateway_ip = None
        config_file = '.config'

        # load router IP from config file
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                for line in f:
                    if line.startswith('router='):
                        gateway_ip = line.split('=')[1].strip()
                        break

        # check if MITM is needed (if target is specified and different from self)
        needs_mitm = target and target != my_ip_addr and target != ''

        if needs_mitm:
            # attempt ARP spoofing for MITM
            success, message = arp_module.start_arp_spoof(target, gateway_ip)
            if not success:
                return render_template("sniffer.html", 
                                      message=f"ARP Spoof Error: {message}",
                                      status_type='error',
                                      devices=[])
            # allow time for poisoning to take effect
            time.sleep(3)

        try:
            # sniff packets for specified duration
            sniff_module.sniffer(pcap_filename, time=duration)
        finally:
            # always stop ARP spoofing afterward
            if needs_mitm:
                arp_module.stop_arp_spoof()

        # move capture to captures folder
        os.makedirs('captures', exist_ok=True)
        pcap_path = f'captures/{pcap_filename}'
        shutil.move(pcap_filename, pcap_path)

        # filter MITM traffic first if needed
        if needs_mitm:
            sniff_module.filter_mitm_traffic(pcap_path, target)

        # analyze capture to generate statistics
        sniff_module.analyze_pcap(pcap_path)

        # move generated CSVs with timestamp
        csv_files = ['protocols.csv', 'top_ips.csv', 'top_ports.csv', 'dns_queries.csv']
        for csv_file in csv_files:
            if os.path.exists(csv_file):
                new_name = csv_file.replace('.csv', f'_{timestamp}.csv')
                shutil.move(csv_file, f'captures/{new_name}')

        # read protocol stats from CSV for display
        stats = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'arp': 0}
        protocols_csv = f'captures/protocols_{timestamp}.csv'

        with open(protocols_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                proto = row['Protocol'].lower()
                count = int(row['Count'])
                stats['total'] += count
                if proto in stats:
                    stats[proto] = count

        # apply protocol filter if selected
        if protocol_filter:
            sniff_module.filter_packets(pcap_path, protocol_filter)

        # note if MITM mode used
        mitm_note = f" (MITM: {target})" if needs_mitm else ""

        # return results with statistics
        return render_template("sniffer.html", 
                             stats=stats, 
                             message=f"Successfully captured {stats['total']} packets{mitm_note}",
                             status_type='success',
                             pcap_file=pcap_filename,
                             devices=[])

    except Exception as e:
        # stop ARP spoofing if error occurred
        try:
            arp_module.stop_arp_spoof()
        except:
            pass

        return render_template("sniffer.html", 
                             message=f"Error: {str(e)}",
                             status_type='error',
                             devices=[])

# sniffer analysis; Load and analyze selected PCAP file

@app.route("/sniffer/analysis", methods=["GET", "POST"], endpoint="sniffer_analysis")
def sniffer_analysis():
    """Handle packet analysis page with detailed statistics"""
    # ensure captures directory exists
    captures_dir = 'captures'
    if not os.path.exists(captures_dir):
        os.makedirs(captures_dir)

    # load list of captured PCAP files
    pcap_files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')]
    pcap_files.sort(reverse=True)

    analysis_data = None
    filename = request.args.get('filename')

    # use selected or most recent file
    if not filename and pcap_files:
        filename = pcap_files[0]

    if filename:
        pcap_path = os.path.join(captures_dir, filename)

        # extract timestamp to find matching CSV files
        timestamp = filename.replace('capture_', '').replace('.pcap', '')
        protocols_csv = f'protocols_{timestamp}.csv'
        ips_csv = f'top_ips_{timestamp}.csv'
        ports_csv = f'top_ports_{timestamp}.csv'
        dns_csv = f'dns_queries_{timestamp}.csv'

        # generate analysis if CSVs not found
        if not os.path.exists(f'captures/{protocols_csv}'):
            sniff_module.analyze_pcap(pcap_path)
            for csv_file in ['protocols.csv', 'top_ips.csv', 'top_ports.csv', 'dns_queries.csv']:
                if os.path.exists(csv_file):
                    new_name = csv_file.replace('.csv', f'_{timestamp}.csv')
                    shutil.move(csv_file, f'captures/{new_name}')

        # read protocols CSV
        protocols = []
        total_packets = 0
        with open(f'captures/{protocols_csv}', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                count = int(row['Count'])
                total_packets += count
                protocols.append(row)

        # add percentage field for visualization
        for proto in protocols:
            proto['Percentage'] = round((int(proto['Count']) / total_packets * 100), 1) if total_packets > 0 else 0

        # read top IPs
        top_ips = []
        unique_ips = set()
        if os.path.exists(f'captures/{ips_csv}'):
            with open(f'captures/{ips_csv}', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    top_ips.append(row)
                    unique_ips.add(row['IP Address'])

        # read top ports
        top_ports = []
        unique_ports = set()
        if os.path.exists(f'captures/{ports_csv}'):
            with open(f'captures/{ports_csv}', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    top_ports.append(row)
                    unique_ports.add(row['Port'])

        # read DNS queries
        dns_queries = []
        if os.path.exists(f'captures/{dns_csv}'):
            with open(f'captures/{dns_csv}', 'r') as f:
                reader = csv.DictReader(f)
                dns_queries = list(reader)

        # combine analysis data for template
        analysis_data = {
            'filename': filename,
            'total_packets': total_packets,
            'unique_ips': len(unique_ips),
            'unique_ports': len(unique_ports),
            'protocols': protocols,
            'top_ips': top_ips,
            'top_ports': top_ports,
            'dns_queries': dns_queries,
            'protocols_csv': protocols_csv,
            'ips_csv': ips_csv,
            'ports_csv': ports_csv,
            'dns_csv': dns_csv if dns_queries else None
        }

    return render_template("sniffer_analysis.html", 
                         pcap_files=pcap_files,
                         analysis=analysis_data,
                         selected_file=filename)

# download files
@app.route('/download/<filename>')
def download_file(filename):
    """Handle file downloads for reports"""
    # map filenames to storage paths
    file_paths = {
        'saved_devices.csv': os.path.join(parent_dir, 'CSV/saved_devices.csv'),
        'performance_log.csv': os.path.join(parent_dir, 'CSV/performance_log.csv'),
        'output.pcap': os.path.join(parent_dir, 'Functions/output.pcap'),
        'scan.log': os.path.join(parent_dir, 'scheduled_logs/scan.log'),
        'performance.log': os.path.join(parent_dir, 'scheduled_logs/performance.log')
    }
    
    # Check if file exists and send for download
    file_path = file_paths.get(filename)
    if file_path and os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

# helper; get local machine's IP
def get_host_ip():
    """Get the local machine's IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

# start web UI
def begin_web_ui():
    """Start the Flask web server"""
    host_ip = get_host_ip()
    print(f"Starting Web UI on http://{host_ip}:1234")
    app.run(host=host_ip, port=1234, debug=False, use_reloader=False)

if __name__ == "__main__":
    begin_web_ui()
