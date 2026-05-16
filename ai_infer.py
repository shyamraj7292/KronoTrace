import os
import joblib
import logging

try:
    AI_SOURCE_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ai_source_model.pkl')
    AI_THREAT_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ai_threat_model.pkl')

    pipeline_src = None
    pipeline_thr = None
    if os.path.exists(AI_SOURCE_MODEL_PATH):
        pipeline_src = joblib.load(AI_SOURCE_MODEL_PATH)
    if os.path.exists(AI_THREAT_MODEL_PATH):
        pipeline_thr = joblib.load(AI_THREAT_MODEL_PATH)
except Exception as e:
    logging.error(f"Failed to load AI model: {e}")
    pipeline_src = None
    pipeline_thr = None

def predict_source(message: str) -> dict:
    """Predict the source system and threat type of an event."""
    result = {
        'source_prediction': 'unknown',
        'threat_prediction': 'benign'
    }

    if pipeline_src is not None:
        try:
            result['source_prediction'] = pipeline_src.predict([message])[0]
        except Exception as e:
            logging.error(f"Source prediction failed: {e}")

    if pipeline_thr is not None:
        try:
            result['threat_prediction'] = pipeline_thr.predict([message])[0]
        except Exception as e:
            logging.error(f"Threat prediction failed: {e}")
            
    return result

import re

def analyze_log(message: str) -> dict:
    """Uses AI to determine the source, and extracts IP, port, and threat accurately."""
    predictions = predict_source(message)
    source_prediction = predictions.get('source_prediction', 'unknown')
    threat_prediction = predictions.get('threat_prediction', 'benign')
    
    # Map the model's source classifications strictly to the Application Name (Fallback)
    app_mapping = {
        "nginx_access": "Nginx Web Server",
        "apache_error": "Apache HTTP Server",
        "linux_auth": "Linux SSH/Auth (sshd)",
        "windows_security": "Windows Active Directory",
        "db_mysql": "MySQL Database",
        "db_postgres": "PostgreSQL Database",
        "application": "Custom Application",
        "unknown": "Unknown Application"
    }

    application_name = ""
    
    # Extract App Name using regex
    app_match = re.search(r'(?:via App|Application:?|App:?)\s*([A-Za-z0-9_\-]+)', message, re.IGNORECASE)
    syslog_app_match = re.search(r'\s([a-zA-Z0-9_\-]+)\[\d+\]:', message)
    
    if app_match:
        application_name = app_match.group(1)
    elif syslog_app_match:
        application_name = syslog_app_match.group(1)
    else:
        application_name = app_mapping.get(source_prediction, "Unknown Application")

    result = {
        "source": source_prediction,
        "threat_type": threat_prediction,
        "application_name": application_name,
        "ip": "",
        "port": ""
    }
    
    # Extract IP address
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)
    if ip_match:
        result["ip"] = ip_match.group(0)
        
    # Extract Port (Looking for common port indicators like 'port 45123' or ':8080')
    port_match = re.search(r'(?:port\s+|:)([1-9][0-9]{0,4})\b', message, re.IGNORECASE)
    if port_match:
        # Check if port is in valid range
        port_num = int(port_match.group(1))
        if 1 <= port_num <= 65535:
            result["port"] = str(port_num)
            
    return result
