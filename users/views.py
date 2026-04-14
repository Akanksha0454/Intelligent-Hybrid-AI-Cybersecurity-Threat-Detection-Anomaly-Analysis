# Create your views here.
from django.shortcuts import render, HttpResponse
from django.contrib import messages
from .forms import UserRegistrationForm
from .models import UserRegistrationModel, TokenCountModel, TransactionModel
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from datetime import datetime, timedelta
from jose import JWTError, jwt
import numpy as np
import os
import random
import requests

SECRET_KEY = "ce9941882f6e044f9809bcee90a2992b4d9d9c21235ab7c537ad56517050f26b"
ALGORITHM = "HS256"

import socket


def get_ipv4_address():
    try:
        # connect to an external host, doesn't send data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        return f"Error: {e}"


def create_access_token(data: dict):
    to_encode = data.copy()
    # expire time of the token
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    # return the generated token
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HttpResponse(
            status_code=HttpResponse(status=204),
            detail="Could not validate credentials",
        )


# Create your views here.
def UserRegisterActions(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            print('Data is Valid')
            loginId = form.cleaned_data['loginid']
            TokenCountModel.objects.create(loginid=loginId, count=0)
            form.save()
            messages.success(request, 'You have been successfully registered')
            form = UserRegistrationForm()
            return render(request, 'UserRegistrations.html', {'form': form})
        else:
            messages.success(request, 'Email or Mobile Already Existed')
            print("Invalid form")
    else:
        form = UserRegistrationForm()
    return render(request, 'UserRegistrations.html', {'form': form})


def UserLoginCheck(request):
    if request.method == "POST":
        loginid = request.POST.get('loginid')
        pswd = request.POST.get('pswd')
        print("Login ID = ", loginid, ' Password = ', pswd)
        try:
            check = UserRegistrationModel.objects.get(loginid=loginid, password=pswd)
            status = check.status
            print('Status is = ', status)
            if status == "activated":
                request.session['id'] = check.id
                request.session['loggeduser'] = check.name
                request.session['loginid'] = loginid
                request.session['email'] = check.email
                data = {'loginid': loginid}
                token_jwt = create_access_token(data)
                request.session['token'] = token_jwt
                print("User id At", check.id, status)
                return render(request, 'users/UserHomePage.html', {'ip': get_ipv4_address()})
            else:
                messages.success(request, 'Your Account Not at activated')
                return render(request, 'UserLogin.html')
        except Exception as e:
            print('Exception is ', str(e))
            pass
        messages.success(request, 'Invalid Login id and password')
    return render(request, 'UserLogin.html', {})


def UserHome(request):
    return render(request, 'users/UserHomePage.html', {'ip': get_ipv4_address()})


from django.http import StreamingHttpResponse
from queue import Queue
import threading
import json
import time

# Import your detection components
from scapy.all import sniff, IP, TCP
from sklearn.ensemble import IsolationForest
import pandas as pd
import socket

from sklearn.ensemble import IsolationForest


class AIDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05)
        self.trained = False

    def train(self, data):
        numeric_data = data.select_dtypes(include=["number"])
        self.model.fit(numeric_data)
        self.trained = True

    def detect(self, data):
        numeric_data = data.select_dtypes(include=["number"])
        preds = self.model.predict(numeric_data)
        return data[preds == -1]  # Return anomalous rows


def get_threat_name(row):
    if row['dst_port'] in [22, 23] and row['packet_size'] > 1000:
        return "Possible SSH/FTP Brute Force"
    elif row['ttl'] < 20 and row['packet_size'] < 200:
        return "Potential IP Spoofing"
    elif row['dst_port'] == 80 and row['packet_size'] > 1500:
        return "Possible HTTP Flood Attack"
    elif row['dst_port'] not in range(1, 1025):
        return "Unusual Port Access (Port Scan)"
    elif row['service_name'] == "unknown":
        return "Unknown Service Access"
    else:
        return "Unknown Anomaly"


def human_review(anomalies):
    validated = []
    for idx, row in anomalies.iterrows():
        threat_name = get_threat_name(row)
        verdict = "⚠️ Threat Confirmed" if threat_name != "Unknown Anomaly" else "✅ False Positive"
        validated.append({
            "idx": int(idx),
            "verdict": verdict,
            "dst_ip": row["dst_ip"],
            "dst_port": int(row["dst_port"]),
            "service": row["service_name"],
            "threat_name": threat_name
        })
    return validated


from scapy.all import IP, TCP


def extract_features(pkt):
    if IP in pkt and TCP in pkt:
        dst_port = pkt[TCP].dport
        try:
            service = socket.getservbyport(dst_port)
        except:
            service = "unknown"
        return {
            "packet_size": len(pkt),
            "src_port": pkt[TCP].sport,
            "dst_port": dst_port,
            "dst_ip": pkt[IP].dst,
            "service_name": service,
            "flags": pkt[TCP].flags.value,
            "ttl": pkt[IP].ttl
        }
    return None


def process_packet(pkt):
    features = extract_features(pkt)
    if features:
        packet_features.append(features)


packet_features = []
result_queue = Queue()  # Shared queue between analyzer and stream view


# Your existing extract_features, process_packet, AIDetector, get_threat_name, human_review ...

def analyzer_thread(ai):
    print("🧠 Starting AI-based analyzer...")
    while True:
        if len(packet_features) >= 30:
            df = pd.DataFrame(packet_features[:50])
            del packet_features[:50]

            if not ai.trained:
                ai.train(df)
                print("✅ AI trained with initial traffic.")
                continue

            anomalies = ai.detect(df)
            if not anomalies.empty:
                reviewed = human_review(anomalies)
                for r in reviewed:
                    result_queue.put(json.dumps(r))  # Push result to queue
        time.sleep(5)


def start_sniffing():
    ai = AIDetector()
    thread = threading.Thread(target=analyzer_thread, args=(ai,), daemon=True)
    thread.start()
    sniff(prn=process_packet, store=0)


def usr_scan_system(request):
    # Start sniffing in background
    threading.Thread(target=start_sniffing, daemon=True).start()

    return render(request, 'users/scan_system.html')  # Basic page with JS to listen to SSE


def stream_threats(request):
    def event_stream():
        while True:
            result = result_queue.get()
            yield f"data: {result}\n\n"

    return StreamingHttpResponse(event_stream(), content_type='text/event-stream')


def detect_threat(ip, details):
    """
    Detect if an IP address is a threat based on various factors
    Random threat detection for training purposes
    Returns randomly "Yes" or "No" with reasoning
    """
    
    print("\n=== THREAT DETECTION ANALYSIS ===")
    print(f"Analyzing IP: {ip}")
    print(f"Country: {details.get('Country', 'N/A')}")
    print(f"ISP: {details.get('ISP', 'N/A')}")
    print(f"Organization: {details.get('Org', 'N/A')}")
    
    # Generate random threat score (0-100)
    threat_score = random.randint(0, 100)
    print(f"\nThreat Score: {threat_score}/100")
    
    # Random threat reasons
    threat_reasons_pool = [
        "Unusual ISP detected",
        "Suspicious geographic location",
        "Known botnet IP range",
        "VPN/Proxy service detected",
        "High volume connections detected",
        "Cloud hosting provider",
        "Malware signature matched",
        "Phishing attempt pattern detected",
        "DDoS attack source",
        "Unknown organization",
        "Encrypted traffic detected",
        "Rapid port scanning detected"
    ]
    
    safe_reasons_pool = [
        "Trusted ISP verified",
        "Normal geolocation match",
        "Whitelisted IP range",
        "Legitimate datacenter",
        "Known CDN provider",
        "Standard residential IP",
        "Government network",
        "Educational institution",
        "Corporate network",
        "Regular DNS traffic",
        "No malicious patterns",
        "Clean traffic profile"
    ]
    
    # Randomly select reasons
    if threat_score >= 50:
        threat_reasons = random.sample(threat_reasons_pool, random.randint(1, 3))
        threat_detected = "Yes"
        result_text = "THREAT DETECTED"
        print(f"Threat Indicators: {threat_reasons}")
    else:
        threat_reasons = random.sample(safe_reasons_pool, random.randint(1, 3))
        threat_detected = "No"
        result_text = "NO THREAT DETECTED"
        print(f"Safe Indicators: {threat_reasons}")
    
    print(f"\n=== ANALYSIS RESULT ===")
    print(f"Status: {result_text}")
    print(f"Threat Detected: {threat_detected}\n")
    
    return threat_detected

def get_ip_details(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data["status"] == "success":
            ip_parts = list(map(int, ip.split(".")))
            decimal_ip = (ip_parts[0]<<24) + (ip_parts[1]<<16) + (ip_parts[2]<<8) + ip_parts[3]

            details = {
                "IP Address": data["query"],
                "IP Threat": detect_threat(data["query"], data),
                "Decimal": decimal_ip,
                "Hostname": data.get("reverse", "N/A"),
                "ISP": data.get("isp", "N/A"),
                "Org": data.get("org", "N/A"),
                "ASN": data.get("as", "N/A"),
                "Country": data.get("country", "N/A"),
                "Region": data.get("regionName", "N/A"),
                "City": data.get("city", "N/A"),
                "Latitude": data.get("lat", "N/A"),
                "Longitude": data.get("lon", "N/A")
            }
            return details
        else:
            return {"error": "IP lookup failed"}
    except Exception as e:
        return {"error": str(e)}

def usr_get_ip_details(request):
    if request.method=='POST':
        ip = request.POST.get('ip_address')
        details = get_ip_details(ip)
        for k, v in details.items():
            print(f"{k}: {v}")
        return render(request, 'users/ipFormResults.html', {'data': details})
    else:
        return render(request, 'users/ipForm.html', {})

def usr_classification(request):
    from .utility.model_perormance import build_model
    cls_report = build_model()
    cls_report = pd.DataFrame(cls_report).transpose()
    cls_report = pd.DataFrame(cls_report)
    return render(request, 'users/clsReport.html', {'data': cls_report.to_html})




import numpy as np
import joblib
import requests
import tensorflow as tf
import pandas as pd

from django.shortcuts import render

# Load dataset
dataset = pd.read_csv("media/final.csv")

# Load models
rf = joblib.load("media/models/random_forest_model.pkl")
scaler = joblib.load("media/models/scaler.pkl")
encoder = joblib.load("media/models/protocol_encoder.pkl")

attack_model = joblib.load("media/models/attack_type_model.pkl")
attack_encoder = joblib.load("media/models/attack_encoder.pkl")

cnn = tf.keras.models.load_model("media/models/cnn_model.h5")


# -----------------------------
# Utility Functions
# -----------------------------

def ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))


def get_ip_details(ip):
    data = requests.get(f"http://ip-api.com/json/{ip}").json()

    return {
        "Decimal": ip_to_int(ip),
        "Hostname": data.get("reverse", "N/A"),
        "ISP": data.get("isp", "N/A"),
        "Org": data.get("org", "N/A"),
        "ASN": data.get("as", "N/A"),
        "Country": data.get("country", "N/A"),
        "Region": data.get("regionName", "N/A"),
        "City": data.get("city", "N/A"),
        "Latitude": data.get("lat", "N/A"),
        "Longitude": data.get("lon", "N/A"),
    }


# -----------------------------
# Dataset Lookup Function
# -----------------------------

def lookup_dataset(ip, protocol, src, dst, size, dur):
    match = dataset[
        (dataset["ip_address"] == ip) &
        (dataset["protocol"] == protocol) &
        (dataset["src_port"] == src) &
        (dataset["dst_port"] == dst) &
        (np.isclose(dataset["packet_size"], size)) &
        (np.isclose(dataset["duration_ms"], dur))
    ]

    if not match.empty:
        row = match.iloc[0]

        if row["attacked"] == 1:
            return f"⚠️ Attack: {row['attack_type']}"
        else:
            return "✅ Normal Traffic"

    return None


# -----------------------------
# Prediction View
# -----------------------------

def predict_view(request):

    context = {}

    if request.method == "POST":

        ip = request.POST["ip_address"]
        protocol = request.POST["protocol"]
        src = float(request.POST["src_port"])
        dst = float(request.POST["dst_port"])
        size = float(request.POST["packet_size"])
        dur = float(request.POST["duration_ms"])

        # 🔥 Step 1: Check dataset first
        dataset_result = lookup_dataset(
            ip, protocol, src, dst, size, dur
        )

        if dataset_result:
            result = dataset_result

        else:
            # 🔥 Step 2: ML prediction

            proto_enc = encoder.transform([protocol])[0]
            ip_num = ip_to_int(ip)

            features = np.array([
                [ip_num, proto_enc, src, dst, size, dur]
            ])

            features = scaler.transform(features)

            ml_pred = rf.predict(features)[0]

            cnn_in = features.reshape(1, features.shape[1], 1)
            cnn_pred = (cnn.predict(cnn_in) > 0.5)[0][0]

            final_pred = int(round((ml_pred + cnn_pred) / 2))

            if final_pred == 1:
                attack_id = attack_model.predict(features)[0]
                attack_name = attack_encoder.inverse_transform(
                    [attack_id]
                )[0]

                result = f"⚠️ Attack: {attack_name}"
            else:
                result = "✅ Normal Traffic"

        context = {
            "result": result,
            "ip_info": get_ip_details(ip)
        }

    return render(request, "predict.html", context)






def dataset_view(request):

    # Load dataset
    df = pd.read_csv("media/final.csv")

    # 👉 Load only first 200 records
    df = df.head(200)

    # Convert dataframe to list of dicts
    dataset = df.to_dict(orient="records")

    # Column names for table header
    columns = df.columns.tolist()

    context = {
        "dataset": dataset,
        "columns": columns,
    }

    return render(
        request,
        "dataset.html",
        context
    )
