import socket
import re
import joblib
import pandas as pd
import tldextract
import whois
import cv2 
import numpy as np
from flask import Flask, request, render_template, redirect, url_for
from datetime import datetime

app = Flask(__name__)

# List of features in the exact order required by the model
cols = [
    "index", "IP_Add", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_Result",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank", "Google_Index",
    "links_pointing", "Statistical_report"
]

try:
    my_model = joblib.load("phishing_model.joblib")
    print("Model loaded successfully!")
except Exception as e:
    my_model = None
    print("Model load error:", e)


def qr_reader(img_file):
    try:
        data_arr = np.frombuffer(img_file.read(), np.uint8)
        img_decoded = cv2.imdecode(data_arr, cv2.IMREAD_COLOR)
        det = cv2.QRCodeDetector()
        val, _, _ = det.detectAndDecode(img_decoded)
        return val
    except:
        return ""


def extract_all_features(url):
    url = url.strip().lower()
    f_dict = {}

    ext = tldextract.extract(url)
    dom_name = ext.domain
    sub_domain = ext.subdomain

    # Part related to the Dot Problem
    has_suspicious_dots = -1
    if ".." in url or url.endswith('.') or url.count('.') > 3 or (sub_domain and sub_domain.count('.') > 0):
        has_suspicious_dots = 1

    good_sites = ['google', 'facebook', 'instagram', 'twitter', 'linkedin', 'whatsapp', 'microsoft', 'apple']
    trusted_flag = 1 if dom_name in good_sites else 0


    # SQL Injection detection
    sql_patterns = [r"union", r"select", r"insert", r"drop", r"truncate", r"waitfor", r"delay", r"'", r"\"" , r"--", r"/\*"]
    sql_found = -1
    for pattern in sql_patterns:
        if re.search(pattern, url):
            sql_found = 1
            

    # XSS Attacks detection
    xss_patterns = [r"<script",r"</script", r"alert\(", r"onerror", r"onload", r"onclick", r"confirm\(", r"prompt\("]
    xss_found = -1
    for pattern in xss_patterns:
        if re.search(pattern, url):
            xss_found = 1
            

    # Brand Impersonation / Typosquatting detection
    look_alike = dom_name.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a')
    spoof_check = -1
    if trusted_flag == 0:
     for site in good_sites:
        if (site in look_alike) and (site != dom_name):
            spoof_check = 1   


    # Suspicious Phishing Keywords
    bad_words = ['login', 'update', 'free', 'verify', 'account', 'download', 'banking', 'pay']
    word_check = 1 if any(w in url for w in bad_words) else -1


    # Feature Extraction
    f_dict["index"] = 0

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        f_dict["IP_Add"] = 1
    else:
        f_dict["IP_Add"] = -1

    if len(url) > 75:
        f_dict["URL_Length"] = 1
    else:
        f_dict["URL_Length"] = -1

    if re.search(r"bit\.ly|goo\.gl|t\.co|tinyurl", url):
        f_dict["Shortining_Service"] = 1
    else:
        f_dict["Shortining_Service"] = -1

    if "@" in url:
        f_dict["having_At_Symbol"] = 1
    else:
        f_dict["having_At_Symbol"] = -1

    if url.rfind("//") > 7:
        f_dict["double_slash_redirecting"] = 1
    else:
        f_dict["double_slash_redirecting"] = -1

    if "-" in dom_name:
        f_dict["Prefix_Suffix"] = 1
    else:
        f_dict["Prefix_Suffix"] = -1

    f_dict["having_Sub_Domain"] = has_suspicious_dots 

    if url.startswith("https"):
        f_dict["SSLfinal_Result"] = -1
    else:
        f_dict["SSLfinal_Result"] = 1

    if re.search(r":[0-9]+", url) and not re.search(r":80|:443", url):
        f_dict["port"] = 1
    else:
        f_dict["port"] = -1

    if "https" in dom_name:
        f_dict["HTTPS_token"] = 1
    else:
        f_dict["HTTPS_token"] = -1

    if (spoof_check == 1 or sql_found == 1 or xss_found == 1 or has_suspicious_dots == 1):
        f_dict["Abnormal_URL"] = 1
    else:
        f_dict["Abnormal_URL"] = -1

    if url.count('/') > 5:
        f_dict["Request_URL"] = 1
    else:
        f_dict["Request_URL"] = -1

    if (has_suspicious_dots == 1 or len(url) > 100):
        f_dict["age_of_domain"] = 1
    else:
        f_dict["age_of_domain"] = -1

    f_dict["Statistical_report"] = word_check

    # Explicit default padding to match the 31-feature model input
    for c in cols:
        if c not in f_dict:
            f_dict[c] = -1

    return f_dict, spoof_check, word_check, sql_found, xss_found, trusted_flag, has_suspicious_dots


@app.route('/')
def home():
    return render_template('Home.html')


@app.route('/index') 
def index():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    file = request.files.get('qr_image')
    text_url = request.form.get('url', '').strip()

    final_url = qr_reader(file) if (file and file.filename != '') else text_url

    if not final_url:
        return redirect(url_for('home'))

    feat, is_spoof, has_words, sql, xss, trust, has_dots = extract_all_features(final_url)
    
    
    my_notes = []
    is_malicious = False
    is_suspicious = False


    #validation Rules 
    # 1. Strict boundary check for trailing or leading dot structures
    raw_clean_url = final_url.strip().lower()
    if raw_clean_url.startswith('.') or raw_clean_url.endswith('.'):
        is_suspicious = True
        my_notes.append("Suspicious Dot Placement at URL Boundary ⚠️")

    #Check malicious vectors BEFORE evaluating brand trust
    if sql == 1:
        is_malicious = True
        my_notes.append("Injection Attack Detected (SQL) 🚨")

    if xss == 1:
        is_malicious = True
        my_notes.append("Attack Detected (XSS) 🚨")    
    
    if is_spoof == 1:
        is_malicious = True
        my_notes.append("Brand Impersonation / Typosquatting ⚠️")

    if feat["IP_Add"] == 1:
        is_malicious = True
        my_notes.append("URL contains direct IP address (Suspicious) 🚨")


    #Whitelist Route 
    if trust == 1 and not is_malicious and not (raw_clean_url.startswith('.') or raw_clean_url.endswith('.')):
        my_notes.append("Trusted Domain ✅")
    else:
        # 4. Machine Learning Decision
        if my_model:
            try:
                df = pd.DataFrame([feat])[cols]
                if my_model.predict(df)[0] == -1:
                    is_malicious = True
                    my_notes.append("AI Model: Phishing Pattern Detected 🤖")
            except:
                pass

       
        if has_dots == 1:
            is_suspicious = True
            if "Suspicious Dot Placement at URL Boundary ⚠️" not in my_notes:
                my_notes.append("Suspicious Dot Pattern / Sub-domain ⚠️")
            
        if has_words == 1:
            is_suspicious = True
            my_notes.append("Suspicious Keywords found in URL ⚠️")

        #Check Website that do not use encryption to protect user data
        if feat["SSLfinal_Result"] == 1:
            is_suspicious = True
            my_notes.append("Missing HTTPS Encryption ❌")

    # 5. Final Tier Mapping
    if is_malicious:
        res_text, res_color, res_level = "Malicious", "#ff4d4d", "CRITICAL"
    elif is_suspicious:
        res_text, res_color, res_level = "Suspicious", "#fbbf24", "WARNING"
    else:
        res_text, res_color, res_level = "Safe", "#10b981", "CLEAN"


    #send result to the interfaces 
    return render_template('index.html', 
                           url_sent=final_url, 
                           prediction_text=res_text, 
                           res_color=res_color, 
                           risk_level=res_level, 
                           reasons=my_notes)

#Running the app
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

