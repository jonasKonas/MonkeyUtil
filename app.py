from flask import Flask, render_template, request, send_file, redirect, url_for
from datetime import datetime
import pandas as pd
import io
import ipaddress



app = Flask(__name__)



######## LANDING PAGE ######## 
# In your Flask application's index route:
@app.route('/')
def index():
    # --- Check Point Tools Data ---
    checkpoint_tools = [
        {
            'title': 'Add Host Objects',
            'desc': 'Generate API commands for adding new IP-based Host objects to groups. Input: IP or Name,IP (comma-separated).',
            # NOTE: url_for() uses the Python function name
            'url': url_for('add_host_api'), 
            'status': 'primary',
            'note': ''
        },
        {
            'title': 'Add Network Objects',
            'desc': 'Generate API commands for adding new network objects to groups. Input: Subnet or Name,Subnet (comma-separated).',
            # This is the previously corrected endpoint name
            'url': url_for('add_networks_api'),
            'status': 'primary',
            'note': ''
        },
        {
            'title': 'Add DNS Domain Objects',
            'desc': "Generate API commands for adding new DNS Domain objects (must start with '.') to groups.",
            'url': url_for('add_dns_domain_api'),
            'status': 'primary',
            'note': ''
        },
        {
            'title': 'Policy Review',
            'desc': 'Review your Check Point Policy by uploading CSV file from SmartConsole.',
            'url': url_for('policy_review'),
            'status': 'primary',
            'note': '- TESTING'
        },
    ]

    # --- Other Vendor Tools Data ---
    other_tools = [
        {
            'title': 'Palo Alto Tool',
            'desc': 'Tools for managing Palo Alto firewall configurations and objects.',
            'url': '#',
            'status': 'secondary',
            'disabled': True,
            'note': '(Coming Soon)'
        }
    ]
    
    return render_template('index.html', checkpoint_tools=checkpoint_tools, other_tools=other_tools)

######## ABOUT PAGE ######## 
@app.route('/about')
def about():
    return render_template('about.html', current_year=datetime.now().year)

#### Change CIDR Notation Function ####
def convert_cidr_to_network_and_mask(cidr_input):
    """
    Converts a CIDR string (e.g., '192.168.22.0/24') into
    the network address and the subnet mask.
    """
    try:
        # Create a Python IPv4 Network object
        network_obj = ipaddress.IPv4Network(cidr_input, strict=False) 
        
        # network_address is the base address of the subnet (e.g., 192.168.22.0)
        network_address = str(network_obj.network_address)
        
        # netmask is the subnet mask (e.g., 255.255.255.0)
        subnet_mask = str(network_obj.netmask)
        
        return network_address, subnet_mask
    except ValueError:
        # Return None, None if the input is not a valid network/CIDR
        return None, None


######## ADD NETWORKS TOOL ######## 
def generate_commands(command_type, ticket_ref, group_name, input_data):
    """
    Generates API commands based on input data and command type.
    Now supports splitting CIDR for Check Point Network objects.
    """
    output = ""
    lines = input_data.strip().split('\n')
    
    # Define the template for the command based on the type
    if command_type == 'host':
        # Host remains the same
        command_prefix = 'add host name "{name}" ip-address "{value}"'
        network_flag = False
    elif command_type == 'network':
        # Network now uses placeholders for both subnet and mask
        command_prefix = 'add network name "{name}" subnet "{subnet}" subnet-mask "{mask}"'
        network_flag = True
    else:
        return "# Error: Invalid command type."

    for line in lines:
        line = line.strip()
        if not line:
            continue

        parts = [p.strip() for p in line.split(',')]
        
        # Determine Name and Value (IP/CIDR)
        if len(parts) == 2:
            name, value = parts
        elif len(parts) == 1:
            value = parts[0]
            # Use auto-generated name for single value input
            name = f'N_{value}' if network_flag else f'H_{value}'
        else:
            output += f"# Skipping invalid line: {line}\n"
            continue # Skip to the next line

        # --- NETWORK COMMAND GENERATION LOGIC ---
        if network_flag:
            subnet, mask = convert_cidr_to_network_and_mask(value)
            
            if subnet is None:
                output += f"# Skipping invalid network/CIDR format: {value}\n"
                continue

            # Format the final network command
            output += f'{command_prefix.format(name=name, subnet=subnet, mask=mask)} comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'

        # --- HOST COMMAND GENERATION LOGIC ---
        else:
            # Check for domain-like input (only relevant for the original host logic)
            if value.startswith('.'):
                 output += f"# Skipping domain-like input: {value} (Use DNS Domain Tool)\n"
                 continue
                 
            # Format the final host command
            output += f'{command_prefix.format(name=name, value=value)} comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'
            
    return output

# --- FLASK ROUTE FUNCTIONS ---

@app.route('/checkpoint/add_networks_api', methods=['GET', 'POST'])
def add_networks_api():
    output = ""
    if request.method == 'POST':
        ticket_ref = request.form.get('ticket_ref', '')
        group_name = request.form.get('group_name', '')
        input_data = request.form.get('input_data', '')

        # Call the centralized helper function for 'network'
        output = generate_commands('network', ticket_ref, group_name, input_data)
        
    return render_template('/checkpoint/add_network_api.html', output=output)


@app.route('/checkpoint/add_host_api', methods=['GET', 'POST'])
def add_host_api():
    output = ""
    if request.method == 'POST':
        ticket_ref = request.form.get('ticket_ref', '')
        group_name = request.form.get('group_name', '')
        input_data = request.form.get('input_data', '')

        # Call the centralized helper function for 'host'
        output = generate_commands('host', ticket_ref, group_name, input_data)
        
    return render_template('/checkpoint/add_host_api.html', output=output)


########  New route for adding DNS Domain Objects ######## 
@app.route('/checkpoint/add_dns_domain_api', methods=['GET', 'POST'])
def add_dns_domain_api():
    output = ""
    if request.method == 'POST':
        ticket_ref = request.form.get('ticket_ref', '')
        group_name = request.form.get('group_name', '')
        input_data = request.form.get('input_data', '')
        # Only relevant option for DNS domains
        is_sub_domain = 'true' if request.form.get('is_sub_domain') == 'on' else 'false'

        lines = input_data.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue  # skip empty lines

            # Must be a single value and start with a dot
            if line.startswith('.'):
                domain_name = line
                output += f'add dns-domain name "{domain_name}" is-sub-domain {is_sub_domain} comments "Ref:{ticket_ref}"\n'
                output += f'set group name "{group_name}" members.add "{domain_name}"\n'
            else:
                output += f"# Skipping non-domain input: {line} (Use Host Tool)\n"

    # NOTE: You will need to create a new template file for this route
    return render_template('/checkpoint/add_dns_domain_api.html', output=output)


#POLICY REVIEW TOOL ___START___

# Weak protocols list
WEAK_PROTOCOLS = ["HTTP", "FTP", "TELNET", "RDP", "POP3", "IMAP"]

def classify_rules(df):
    """
    Classifies rules into one or more categories:
    - Section Header (NEW)
    - Disabled (Type contains "[Disabled]")
    - Zero Hits
    - Any in Source/Destination
    - Weak Protocol
    Adds a new column 'Categories' (list of tags) and 'is_section' flag.
    """
    results = []
    
    # Assuming WEAK_PROTOCOLS is defined globally or passed in
    global WEAK_PROTOCOLS # If defined outside the function

    for _, row in df.iterrows():
        rule = row.to_dict()  # keep all original columns
        categories = []

        # 1. SECTION CHECK (Must be inside the for loop)
        if str(row.get("Type", "")).strip().lower() == "section":
            rule['is_section'] = True
            categories.append("Section Header")
            
            # FIX: Safely retrieve Section Name
            section_display_name = str(row.get("Name", "")).strip()
            
            if not section_display_name or section_display_name.lower() == 'nan':
                 # Fallback to Source column if Name is blank/NaN (common CP export issue)
                 section_display_name = f"SECTION: {row.get('Source', 'Unnamed Section')}"
            
            # Use a guaranteed key for HTML display
            rule['SectionDisplayName'] = section_display_name.upper()

            # Fill other keys with empty string to prevent NaNs in the final data
            for key in rule.keys():
                # Check for NaN/None and that it's not one of our new keys
                if key not in ['Name', 'Type', 'is_section', 'SectionDisplayName'] and (pd.isna(rule.get(key)) or rule.get(key) is None):
                    rule[key] = ''
            
            rule["Categories"] = ", ".join(categories)
            results.append(rule)
            continue  # Move to the next row in the loop (correct use)
        
        # 2. REGULAR RULE LOGIC (Only runs if the row is NOT a section)
        
        rule['is_section'] = False # Tag normal rules explicitly

        # Disabled check
        if "[disabled]" in str(row.get("Type", "")).lower():
            categories.append("Disabled")
            
        # Zero Hits check
        if str(row.get("Hits", "")).strip().lower() == "zero":
            categories.append("Zero Hits")
            
        # Any in Source or Destination
        if str(row.get("Source", "")).strip().lower() == "any" or str(row.get("Destination", "")).strip().lower() == "any":
            categories.append("Any in Source/Destination")
            
        # Weak Protocols (split by ;)
        services = str(row.get("Services & Applications", ""))
        service_tokens = [s.strip().lower() for s in services.split(";")]
        for proto in WEAK_PROTOCOLS:
            if proto.lower() in service_tokens:
                categories.append("Weak Protocol")
                break
                
        # If nothing matched → Normal
        if not categories:
            categories = ["Normal"]
            
        # Store as comma-separated string for HTML/CSV
        rule["Categories"] = ", ".join(categories)
        results.append(rule)

    return results

# Updated policy_review route
@app.route("/checkpoint/policy_review", methods=["GET", "POST"])
def policy_review():
    global classified_rules
    classified_rules = None
    results = None
    
    # 💡 FIX: Initialize the variable that will be passed to the template
    results_for_html = None 

    if request.method == "POST":
        file = request.files.get("csv_file")
        if file and file.filename.endswith(".csv"):
            df = pd.read_csv(file)
            df = df.fillna("")  # Replace NaN with empty strings
            
            # --- The classification happens here ---
            results = classify_rules(df)
            classified_rules = results  # store for download
            
            # Create a new list where each rule dictionary has 'is_section' removed
            results_for_html = []
            for rule in results:
                # Create a copy and remove the key if it exists
                temp_rule = rule.copy()
                temp_rule.pop('is_section', None) 
                temp_rule.pop('SectionDisplayName', None) 
                results_for_html.append(temp_rule)
            
    # Pass the list (which is [] or None on GET, and contains data on POST) to the template
    return render_template("/checkpoint/policy_review.html", rules=results_for_html)

#Download reviewed rules
@app.route("/download_policy", methods=["POST"])
def download_policy():
    global classified_rules
    if not classified_rules:
        return "No classified rules to download.", 400

    # 💡 FIX: Clean the data *before* converting to DataFrame (essential for download)
    cleaned_for_download = []
    for rule in classified_rules:
        temp_rule = rule.copy()
        
        # Remove the internal display flag
        temp_rule.pop('is_section', None) 
        
        # REMOVE THE COLUMN FROM THE CSV OUTPUT
        temp_rule.pop('SectionDisplayName', None)
        
        cleaned_for_download.append(temp_rule)

    # Convert the cleaned list of dicts to DataFrame
    df = pd.DataFrame(cleaned_for_download)

    # Create in-memory CSV
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Get current date/time for filename
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"classified_rules_{date_str}.csv"
    )
#POLICY REVIEW TOOL ___END___

