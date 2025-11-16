from flask import Flask, render_template, request, send_file, redirect, url_for
from datetime import datetime
import pandas as pd
import io



app = Flask(__name__)



#LANDING PAGE
@app.route('/')
def index():
    return render_template('index.html', current_year=datetime.now().year)

#ABOUT PAGE
@app.route('/about')
def about():
    return render_template('about.html', current_year=datetime.now().year)



# Route for adding Host Objects
@app.route('/checkpoint/add_host_api', methods=['GET', 'POST'])
def add_host_api():
    output = ""
    if request.method == 'POST':
        ticket_ref = request.form.get('ticket_ref', '')
        group_name = request.form.get('group_name', '')
        input_data = request.form.get('input_data', '')

        lines = input_data.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue  # skip empty lines
            
            # *** KEY CHANGE: Split by comma (',') instead of space ***
            parts = [p.strip() for p in line.split(',')]

            # Host with Name and IP (now separated by a comma)
            if len(parts) == 2:
                name, ip = parts
                output += f'add host name "{name}" ip-address "{ip}" comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'

            # Single value: IP only
            elif len(parts) == 1:
                value = parts[0]
                # Skip if it looks like a domain (starts with .)
                if value.startswith('.'):
                    output += f"# Skipping domain-like input: {value} (Use DNS Domain Tool)\n"
                else:
                    # Treat as IP and auto-generate host name
                    name = f'H_{value}'
                    output += f'add host name "{name}" ip-address "{value}" comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'

            else:
                output += f"# Skipping invalid line: {line}\n"

    return render_template('/checkpoint/add_host_api.html', output=output)

# New route for adding DNS Domain Objects
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
    - Disabled (Type contains "[Disabled]")
    - Zero Hits
    - Any in Source/Destination
    - Weak Protocol
    Adds a new column 'Categories' (list of tags).
    """
    results = []
    for _, row in df.iterrows():
        rule = row.to_dict()  # keep all original columns
        categories = []
        # Section check
if str(row.get("Type", "")).strip().lower() == "section":
        rule['is_section'] = True
        categories.append("Section Header")
        
        # 💡 FIX: Explicitly get the section name from the 'Name' column, 
        # or use a fallback if that column is unexpectedly blank (NaN).
        section_display_name = str(row.get("Name", "")).strip()
        
        if not section_display_name or section_display_name.lower() == 'nan':
             # If 'Name' is blank or NaN, use the 'Type' and 'Source' as a fallback
             section_display_name = f"SECTION: {row.get('Source', 'Unnamed Section')}"
        
        # Add a new key for the HTML to use directly, ensuring it's not 'nan'
        rule['SectionDisplayName'] = section_display_name.upper()

        # Fill other keys with empty string to prevent NaNs in the final data
        for key in rule.keys():
             if key not in ['Name', 'Type', 'is_section', 'SectionDisplayName'] and (pd.isna(rule.get(key)) or rule.get(key) is None):
                 rule[key] = '' 
        
        # ... rest of the section logic
        rule["Categories"] = ", ".join(categories)
        results.append(rule)
        continue  # Skip all other checks for a section
    else:
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
    
#DOWNLOAD_FUNCTION_FOR_POLICY_REVIEW
# Global store for download
classified_rules = None

@app.route("/checkpoint/policy_review", methods=["GET", "POST"])
def policy_review():
    global classified_rules
    classified_rules = None
    results = None

    if request.method == "POST":
        file = request.files.get("csv_file")
        if file and file.filename.endswith(".csv"):
            df = pd.read_csv(file)
            results = classify_rules(df)
            classified_rules = results  # store for download

    return render_template("/checkpoint/policy_review.html", rules=results)

#Download reviewed rules
@app.route("/download_policy", methods=["POST"])
def download_policy():
    global classified_rules
    if not classified_rules:
        return "No classified rules to download.", 400

    # Convert list of dicts to DataFrame
    df = pd.DataFrame(classified_rules)

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

