import os
import re
import csv
import json
import requests
import subprocess
import zipfile
import pandas as pd
from datetime import datetime
from jinja2 import Environment, select_autoescape
OUTPUT_DIR = "sonarqube_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

class SonarQubeConfig:
    def __init__(self, sonarqube_url, username, password, project_key, github_repo_clone_url,
                 clone_dir_base="cloned_repos", output_dir_base="sonarqube_output",
                 vul_config_json_path="vul.json", threshold_score=20):

        self.SONARQUBE_URL = sonarqube_url
        self.USERNAME = username
        self.PASSWORD = password
        self.PROJECT_KEY = project_key
        self.GITHUB_URL = github_repo_clone_url

        match = re.search(r'github\.com/([^/]+/[^/]+?)(\.git)?$', github_repo_clone_url)
        self.GITHUB_REPO = match.group(1) if match else "unknown_repo"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.TIMESTAMP = timestamp

        unique_project_slug = re.sub(r'[^a-zA-Z0-9_-]', '_', self.PROJECT_KEY)
        self.CLONE_DIR = os.path.join(clone_dir_base, f"{unique_project_slug}_{timestamp}")
        self.OUTPUT_DIR = os.path.join(output_dir_base, f"{unique_project_slug}output{timestamp}")
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

        self.CONFIG_JSON_PATH = vul_config_json_path
        self.THRESHOLD_SCORE = int(threshold_score)

        self.EXTRACTED_CODE_JSON = os.path.join(self.OUTPUT_DIR, f"hotspots_with_code_{timestamp}.json")
        self.EXTRACTED_CODE_CSV = os.path.join(self.OUTPUT_DIR, f"hotspots_with_code_{timestamp}.csv")
        self.FINAL_REPORT_CSV = os.path.join(self.OUTPUT_DIR, f"final_report_{timestamp}.csv")
        self.FINAL_REPORT_HTML = os.path.join(self.OUTPUT_DIR, f"final_report_{timestamp}.html")
        self.ALL_ISSUES_CSV = os.path.join(self.OUTPUT_DIR, f"all_issues_{timestamp}.csv")
        self.ALL_ISSUES_HTML = os.path.join(self.OUTPUT_DIR, f"all_issues_{timestamp}.html")

        self.status_updates = []

    def _add_status(self, message):
        print(message)
        self.status_updates.append(message)


def fetch_hotspots(sq_config):
    sq_config._add_status(f"Fetching hotspots for project {sq_config.PROJECT_KEY}...")
    api_url = f"{sq_config.SONARQUBE_URL}/api/hotspots/search"
    params = {"projectKey": sq_config.PROJECT_KEY, "status": "TO_REVIEW", "ps": 500}

    hotspots = []
    page = 1
    while True:
        params["p"] = page
        try:
            resp = requests.get(api_url, params=params, auth=(sq_config.USERNAME, sq_config.PASSWORD), timeout=30)
            resp.raise_for_status()
        except requests.RequestException as e:
            sq_config._add_status(f"Request failed: {e}")
            return None

        data = resp.json()
        new_hotspots = data.get("hotspots", [])
        if not new_hotspots:
            break
        hotspots.extend(new_hotspots)

        if len(hotspots) >= data.get("paging", {}).get("total", len(hotspots)):
            break
            
        page += 1
        if page > 20:
            break

    sq_config._add_status(f"Total hotspots fetched: {len(hotspots)}")
    return hotspots


def fetch_summary_metrics(sq_config):
    sq_config._add_status("Fetching summary metrics from SonarQube...")
    api_url = f"{sq_config.SONARQUBE_URL}/api/measures/component"
    params = {
        "component": sq_config.PROJECT_KEY,
        "metricKeys": ",".join([
            "bugs", "vulnerabilities", "code_smells", "security_rating", "reliability_rating",
            "sqale_rating", "duplicated_lines_density", "coverage", "ncloc", "security_hotspots",
            "violations", "alert_status"
        ])
    }

    explanations = {
        "coverage": "Lines covered by tests.",
        "alert_status": "Quality Gate status.",
        "bugs": "Number of bugs.",
        "reliability_rating": "Reliability rating.",
        "code_smells": "Maintainability issues.",
        "duplicated_lines_density": "Duplicate code %.",
        "security_rating": "Security rating.",
        "ncloc": "Non-comment lines of code.",
        "violations": "Total violations.",
        "vulnerabilities": "Security problems.",
        "security_hotspots": "Potential vulnerabilities.",
        "sqale_rating": "Maintainability rating."
    }

    try:
        resp = requests.get(api_url, params=params, auth=(sq_config.USERNAME, sq_config.PASSWORD), timeout=30)
        resp.raise_for_status()
        return [
            {"Metric": m["metric"], "Value": m["value"], "Explanation": explanations.get(m["metric"], "")}
            for m in resp.json()["component"]["measures"]
        ]
    except Exception as e:
        sq_config._add_status(f"Failed to fetch summary metrics: {str(e)}")
        return []


def fetch_rule_metadata(rule_key, sq_config):
    url = f"{sq_config.SONARQUBE_URL}/api/rules/show"
    try:
        resp = requests.get(url, params={"key": rule_key}, auth=(sq_config.USERNAME, sq_config.PASSWORD), timeout=10)
        resp.raise_for_status()
        rule = resp.json().get("rule", {})
        tags = rule.get("tags", [])
        name = rule.get("name", "")
        description = rule.get("htmlDesc", "")

        # Try to extract CVE from tags or rule description
        cve_matches = [tag for tag in tags if tag.upper().startswith("CVE")]
        if not cve_matches:
            cve_matches = re.findall(r'(CVE-\d{4}-\d+)', name + " " + description)
        return ", ".join(set(cve_matches)) if cve_matches else ""

    except Exception as e:
        sq_config._add_status(f"Failed to fetch rule metadata for {rule_key}: {e}")
        return ""


def extract_code_for_hotspots(hotspots, sq_config):
    filtered_hotspots = []
    for h in hotspots:
        file_match = re.search(r':([^:]+)$', h.get("component", ""))
        file_path = file_match.group(1) if file_match else None

        if file_path and file_path.endswith("sonarqube.py"):
            continue
        if not file_path:
            h["extracted_code"] = "Invalid component path"
            continue

        full_path = os.path.join(sq_config.CLONE_DIR, file_path)
        line = int(h.get("line", 1))

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()
        except Exception:
            h["extracted_code"] = "Error reading file"
            continue

        start = max(0, line - 11)
        end = min(len(lines), line + 10)
        h["extracted_code"] = "\n".join(lines[start:end])
        h["start_line"] = start + 1
        h["end_line"] = end

        filtered_hotspots.append(h)

    return filtered_hotspots


def save_hotspots_to_file(sq_config, hotspots, path_json, path_csv, label="data"):
    fieldnames = ['key', 'component', 'line', 'message', 'ruleKey', 'vulnerabilityProbability',
                  'extracted_code', 'start_line', 'end_line']

    # Always write JSON file (even if empty list)
    with open(path_json, 'w', encoding='utf-8') as f:
        json.dump(hotspots if hotspots else [], f, indent=4)

    # Always write CSV (header even if empty)
    with open(path_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        if hotspots:
            for h in hotspots:
                writer.writerow({k: h.get(k, "") for k in fieldnames})

    sq_config._add_status(f"Saved {label} to {path_csv}" if hotspots else f"No {label} to save. Created empty CSV at {path_csv}")


def write_html_report(filtered_csv, summary_data, output_path, sq_config):
    try:
        df_vul = pd.read_csv(filtered_csv)
        df_summary = pd.DataFrame(summary_data)
        if df_summary.empty:
            df_summary = pd.DataFrame(columns=["Metric", "Value", "Explanation"])
        else:
            df_summary["Value"] = df_summary["Value"].astype(str)

        html_template = """
        <html>
        <head>
        <style>
        body { font-family: Arial; padding: 20px; }
        h1, h2 { color: #2E6C80; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
        th, td { border: 1px solid #ccc; padding: 8px; }
        th { background-color: #f2f2f2; }
        pre { background: #f9f9f9; border: 1px solid #ccc; padding: 10px; overflow-x: auto; }
        </style>
        </head>
        <body>
        <h1>SonarQube Final Report</h1>
        <h2>Summary Metrics</h2>
        <table>
        <tr>{% for col in summary.columns %}<th>{{ col }}</th>{% endfor %}</tr>
        {% for _, row in summary.iterrows() %}
        <tr>{% for col in summary.columns %}<td>{{ row[col] }}</td>{% endfor %}</tr>
        {% endfor %}
        </table>
        <h2>Security Hotspots</h2>
        {% if vul.empty %}
            <p><i>No security hotspots found.</i></p>
        {% else %}
        <table>
        <tr>{% for col in vul.columns %}<th>{{ col }}</th>{% endfor %}</tr>
        {% for _, row in vul.iterrows() %}
        <tr>
            {% for col in vul.columns %}
                <td>{% if col == 'extracted_code' %}<pre>{{ row[col] }}</pre>{% else %}{{ row[col] }}{% endif %}</td>
            {% endfor %}
        </tr>
        {% endfor %}
        </table>
        {% endif %}
        </body>
        </html>
        """

        env = Environment(autoescape=select_autoescape(['html', 'xml']))
        template = env.from_string(html_template)  
        html = template.render(summary=df_summary, vul=df_vul)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        sq_config._add_status(f"HTML report written: {output_path}")
    except Exception as e:
        sq_config._add_status(f"Failed to write HTML report: {e}")


def write_final_combined_csv_report(filtered_csv, summary_data, output_path, sq_config):
    try:
        df_vul = pd.read_csv(filtered_csv)
        df_summary = pd.DataFrame(summary_data)

        # FIX: Handle empty summary safely
        if df_summary.empty:
            df_summary = pd.DataFrame(columns=["Metric", "Value", "Explanation"])
        else:
            df_summary["Value"] = df_summary["Value"].astype(str)

        with open(output_path, "w", encoding="utf-8", newline="") as f:
            df_vul.to_csv(f, index=False)
            f.write("\n\n--- SonarQube Summary Metrics ---\n\n")
            df_summary.to_csv(f, index=False)

        sq_config._add_status(f"Final CSV report written: {output_path}")
    except Exception as e:
        sq_config._add_status(f"Failed to write CSV report: {e}")



def fetch_all_issues(sq_config):
    sq_config._add_status(f"Fetching ALL issues for {sq_config.PROJECT_KEY}...")
    issues = []
    page = 1
    while True:
        url = f"{sq_config.SONARQUBE_URL}/api/issues/search"
        params = {
            "componentKeys": sq_config.PROJECT_KEY,
            "ps": 500,
            "p": page,
            "additionalFields": "_all"
        }
        try:
            resp = requests.get(url, params=params, auth=(sq_config.USERNAME, sq_config.PASSWORD), timeout=30)
            resp.raise_for_status()
            data = resp.json()
            issues += data.get("issues", [])
            if page * 500 >= data.get("total", 0):
                break
            page += 1
        except Exception as e:
            sq_config._add_status(f"Failed to fetch issues: {e}")
            break

    sq_config._add_status(f"Total issues fetched: {len(issues)}")
    return issues


def extract_vulnerabilities_from_issues(all_issues, sq_config):
    vul_issues = []
    for issue in all_issues:
        if issue.get("component", "").endswith("sonarqube.py"):
            continue
        if issue.get("type") == "VULNERABILITY":
            cve = fetch_rule_metadata(issue.get("rule", ""), sq_config)
            file_path = issue.get("component", "").split(":")[-1]
            line = int(issue.get("line", 1))
            full_path = os.path.join(sq_config.CLONE_DIR, file_path)
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
            except (OSError, IOError):
                code = "Error reading file"
            else:
                start = max(0, line - 11)
                end = min(len(lines), line + 10)
                code = "\n".join(lines[start:end])

            vul_issues.append({
                "key": issue.get("key", ""),
                "component": issue.get("component", ""),
                "line": line,
                "message": issue.get("message", ""),
                "ruleKey": issue.get("rule", ""),
                "vulnerabilityProbability": "",
                "extracted_code": code,
                "start_line": start + 1,
                "end_line": end,
                "CVE": cve,
            })

    sq_config._add_status(f"Extracted {len(vul_issues)} vulnerabilities from all issues.")
    return vul_issues


def save_all_issues_to_csv(issues, path, sq_config):
    fieldnames = [
        "File", "Line", "Message", "Type", "Severity", "Effort", "Status",
        "Assignee", "Tags", "Rule", "CVE", "Creation Date", "Update Date"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i in issues:
            cve = ""
            if i.get("type") == "VULNERABILITY":
                cve = fetch_rule_metadata(i.get("rule", ""), sq_config)
            writer.writerow({
                "File": i.get("component", "").split(":")[-1],
                "Line": i.get("line", ""),
                "Message": i.get("message", ""),
                "Type": i.get("type", ""),
                "Severity": i.get("severity", ""),
                "Effort": i.get("effort", ""),
                "Status": i.get("status", ""),
                "Assignee": i.get("assignee", "Unassigned"),
                "Tags": ", ".join(i.get("tags", [])),
                "Rule": i.get("rule", ""),
                "CVE": cve,
                "Creation Date": i.get("creationDate", ""),
                "Update Date": i.get("updateDate", "")
            })
    sq_config._add_status(f"Issue report written: {path}")


# def write_all_issues_to_html(issues_csv, output_path, sq_config):
#     try:
#         df = pd.read_csv(issues_csv)
#         if df.empty:
#             html_content = "<html><body><h2>No issues found</h2></body></html>"
#         else:
#             df_by_type = {k: v for k, v in df.groupby("Type")}
#             html_template = """
#             <html>
#             <head>
#             <style>
#             body { font-family: Arial; padding: 20px; }
#             h1, h2 { color: #2E6C80; }
#             .issue-type-section { margin-bottom: 40px; }
#             .issue-card { border: 1px solid #ccc; padding: 12px; margin-bottom: 15px;
#                           border-left: 6px solid #2E6C80; background-color: #f9f9f9; }
#             .issue-header { font-weight: bold; margin-bottom: 6px; }
#             .issue-meta { font-size: 13px; color: #555; margin-bottom: 4px; }
#             pre { background: #fff; padding: 8px; border: 1px dashed #ccc; }
#             </style>
#             </head>
#             <body>
#             <h1>Detailed Issue Report</h1>
#             {% for issue_type, issues in grouped_issues.items() %}
#             <div class="issue-type-section">
#                 <h2>{{ issue_type }}</h2>
#                 {% for _, row in issues.iterrows() %}
#                 <div class="issue-card">
#                     <div class="issue-header">{{ row['Message'] }}</div>
#                     <div class="issue-meta"><b>File:</b> {{ row['File'] }} &nbsp;&nbsp;
#                         <b>Line:</b> {{ row['Line'] }}</div>
#                     <div class="issue-meta"><b>Severity:</b> {{ row['Severity'] }} &nbsp;&nbsp;
#                         <b>Effort:</b> {{ row['Effort'] }}</div>
#                     <div class="issue-meta"><b>Rule:</b> {{ row['Rule'] }} &nbsp;&nbsp;
#                         <b>Status:</b> {{ row['Status'] }}</div>
#                     {% if 'CVE' in row and row['CVE'] %}
#                         <div class="issue-meta"><b>CVE:</b> {{ row['CVE'] }}</div>
#                     {% endif %}
#                     <div class="issue-meta"><b>Tags:</b> {{ row['Tags'] or 'None' }}</div>
#                     <div class="issue-meta"><b>Created:</b> {{ row['Creation Date'] }} &nbsp;&nbsp;
#                         <b>Updated:</b> {{ row['Update Date'] }}</div>
#                 </div>
#                 {% endfor %}
#             </div>
#             {% endfor %}
#             </body>
#             </html>
#             """
#             env = Environment(autoescape=select_autoescape(['html', 'xml']))
#             template = env.from_string(html_template)  
#             rendered_html = template.render(grouped_issues=df_by_type)
#             html_content = rendered_html

#         with open(output_path, 'w', encoding='utf-8') as f:
#             f.write(html_content)

#         sq_config._add_status(f"Grouped HTML issue report written: {output_path}")
#     except Exception as e:
#         sq_config._add_status(f"Failed to write grouped HTML issue report: {e}")
def write_all_issues_to_html(issues_csv, output_path, sq_config):
    try:
        df = pd.read_csv(issues_csv)
        if df.empty:
            html_content = "<html><body><h2>No issues found</h2></body></html>"
        else:
            # Normalize types
            df["Type"] = df["Type"].str.upper()

            # Separate tabs by issue type
            issue_types = ["BUG", "VULNERABILITY", "CODE_SMELL", "HOTSPOT"]
            html_sections = []

            for t in issue_types:
                subset = df[df["Type"] == t]
                if subset.empty:
                    continue
                html_sections.append(f"<h2>{t}s ({len(subset)})</h2>")
                html_sections.append("<table border='1' cellspacing='0' cellpadding='5'>")
                html_sections.append("<tr>" + "".join([f"<th>{c}</th>" for c in subset.columns]) + "</tr>")
                for _, row in subset.iterrows():
                    html_sections.append("<tr>" + "".join([f"<td>{row[c]}</td>" for c in subset.columns]) + "</tr>")
                html_sections.append("</table>")

            html_content = "<html><head><meta charset='UTF-8'></head><body>"
            html_content += "<h1>Detailed Issue Report</h1>"
            html_content += "".join(html_sections)
            html_content += "</body></html>"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        sq_config._add_status(f"Grouped HTML issue report written: {output_path}")
    except Exception as e:
        sq_config._add_status(f"Failed to write grouped HTML issue report: {e}")



def create_zip_report(sq_config):
    zip_path = os.path.join(sq_config.OUTPUT_DIR, f"sonarqube_report_bundle_{sq_config.TIMESTAMP}.zip")
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.write(sq_config.FINAL_REPORT_CSV, arcname=os.path.basename(sq_config.FINAL_REPORT_CSV))
        zipf.write(sq_config.FINAL_REPORT_HTML, arcname=os.path.basename(sq_config.FINAL_REPORT_HTML))
        zipf.write(sq_config.ALL_ISSUES_CSV, arcname=os.path.basename(sq_config.ALL_ISSUES_CSV))
        zipf.write(sq_config.ALL_ISSUES_HTML, arcname=os.path.basename(sq_config.ALL_ISSUES_HTML))
    sq_config._add_status(f"Zipped reports to: {zip_path}")
    return zip_path
    
if __name__ == "__main__":
    project_key = os.getenv("SONAR_PROJECT_KEY")
    github_repo_url = os.getenv("TARGET_REPO_URL")
    sonar_token = os.getenv("SONAR_TOKEN")
    sonar_host = os.getenv("SONAR_HOST_URL")

    if not project_key:
        raise ValueError("SONAR_PROJECT_KEY not provided")

    if not github_repo_url:
        raise ValueError("TARGET_REPO_URL not provided")

    config = SonarQubeConfig(
        sonarqube_url=sonar_host,
        username=sonar_token,
        password="",
        project_key=project_key,
        github_repo_clone_url=github_repo_url
    )

    config.CLONE_DIR = os.getenv("GITHUB_WORKSPACE", config.CLONE_DIR)
    print(f"Using code from: {config.CLONE_DIR}")

    #Fetch hotspots
    hotspots = fetch_hotspots(config)
    hotspots = [h for h in hotspots if not h.get("component", "").endswith("sonarqube.py")]
    hotspots = extract_code_for_hotspots(hotspots, config)

    #Save hotspots only temporarily (don’t keep outside)
    temp_hotspots_json = os.path.join(config.OUTPUT_DIR, f"hotspots_temp.json")
    temp_hotspots_csv = os.path.join(config.OUTPUT_DIR, f"hotspots_temp.csv")
    
    save_hotspots_to_file(config, hotspots, temp_hotspots_json, temp_hotspots_csv, label="hotspots")

    #Fetch all issues
    sonarqube_issues = fetch_all_issues(config)
    sonarqube_issues = [i for i in sonarqube_issues if not i.get("component", "").endswith("sonarqube.py")]

    #Extract vulnerabilities from issues
    vul_from_issues = extract_vulnerabilities_from_issues(sonarqube_issues, config)

    #Merge vulnerabilities with hotspots
    combined_vulnerabilities = vul_from_issues + hotspots

    #Convert hotspots to issue-like format
    hotspot_issues = []
    for h in hotspots:
        hotspot_issues.append({
            "component": h.get("component", ""),
            "line": h.get("line", ""),
            "message": h.get("message", ""),
            "type": "HOTSPOT",
            "severity": "MEDIUM",
            "effort": "",
            "status": "TO_REVIEW",
            "assignee": "",
            "tags": ["hotspot"],
            "rule": h.get("ruleKey", ""),
            "creationDate": "",
            "updateDate": "",
        })
    all_issues = sonarqube_issues + hotspot_issues

    #Fetch summary metrics
    summary = fetch_summary_metrics(config)

    #Temp report paths
    temp_final_csv = os.path.join(config.OUTPUT_DIR, f"final_report_temp.csv")
    temp_final_html = os.path.join(config.OUTPUT_DIR, f"final_report_temp.html")
    temp_all_issues_csv = os.path.join(config.OUTPUT_DIR, f"all_issues_temp.csv")
    temp_all_issues_html = os.path.join(config.OUTPUT_DIR, f"all_issues_temp.html")

    #Write reports
    write_final_combined_csv_report(temp_hotspots_csv, summary, temp_final_csv, config)
    write_html_report(temp_hotspots_csv, summary, temp_final_html, config)
    save_all_issues_to_csv(all_issues, temp_all_issues_csv, config)
    write_all_issues_to_html(temp_all_issues_csv, temp_all_issues_html, config)

    #Create ZIP bundle
    zip_path = os.path.join(config.OUTPUT_DIR, f"sonarqube_report_bundle_{config.TIMESTAMP}.zip")
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.write(temp_final_csv, arcname=os.path.basename(config.FINAL_REPORT_CSV))
        zipf.write(temp_final_html, arcname=os.path.basename(config.FINAL_REPORT_HTML))
        zipf.write(temp_all_issues_csv, arcname=os.path.basename(config.ALL_ISSUES_CSV))
        zipf.write(temp_all_issues_html, arcname=os.path.basename(config.ALL_ISSUES_HTML))
        zipf.write(temp_hotspots_csv, arcname=os.path.basename(config.EXTRACTED_CODE_CSV))
        zipf.write(temp_hotspots_json, arcname=os.path.basename(config.EXTRACTED_CODE_JSON))

    #Cleanup temp files
    os.remove(temp_final_csv)
    os.remove(temp_final_html)
    os.remove(temp_all_issues_csv)
    os.remove(temp_all_issues_html)
    os.remove(temp_hotspots_csv)
    os.remove(temp_hotspots_json)



    print(f"\nZIP Report Path : {zip_path}")
    print(f"\nAll reports are included inside the ZIP bundle.")
