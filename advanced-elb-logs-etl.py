import os
import gzip
import shlex
import time
import requests
import pandas as pd
from io import BytesIO
from datetime import datetime, timezone
import pytz
from urllib.parse import urlparse
from user_agents import parse as ua_parse
from dotenv import load_dotenv

# AWS S3 Configuration
load_dotenv()
AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_BUCKET_NAME       = os.getenv("AWS_BUCKET_NAME")
AWS_LOG_PREFIX        = os.getenv("AWS_LOG_PREFIX", "")
AWS_REGION            = os.getenv("AWS_REGION", "us-west-2")
GEO_CACHE_PATH        = "ip_geolocation_cache.parquet"

OUTPUT_CLEANED        = "output/cleaned_logs"
OUTPUT_AGG            = "output/aggregated_stats"
OUTPUT_REPORTS        = "output/reports"
EASTERN               = pytz.timezone("America/New_York")

for folder in [OUTPUT_CLEANED, OUTPUT_AGG, OUTPUT_REPORTS]:
    os.makedirs(folder, exist_ok=True)

import boto3
s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

# COLUMN DEFINITIONS 
ELB_LOG_COLUMNS = [
    "type", "time", "elb", "client_ip_port", "target_ip_port", "request_processing_time", "target_processing_time",
    "response_processing_time", "elb_status_code", "target_status_code", "received_bytes", "sent_bytes", "request",
    "user_agent", "ssl_cipher", "ssl_protocol", "target_group_arn", "trace_id", "domain_name", "chosen_cert_arn",
    "matched_rule_priority", "request_creation_time", "actions_executed", "redirect_url", "error_reason",
    "target_port_list", "target_status_code_list", "classification", "classification_reason"
]

# Uitility / helper function
def to_int(val):
    if val == '-' or val == "" or val is None:
        return None
    try: return int(val)
    except: return None

def to_float(val):
    if val == '-' or val == "" or val is None:
        return None
    try: return float(val)
    except: return None

# EXTRACT: get .gz keys from S3
def extract_log_keys(bucket, prefix=''):
    paginator = s3.get_paginator('list_objects_v2')
    keys = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys += [obj['Key'] for obj in page.get('Contents', []) if obj['Key'].endswith('.gz')]
    return keys

def parse_log_entry(line: str, source_file: str):
    try:
        parts = shlex.split(line)
        if len(parts) < len(ELB_LOG_COLUMNS):
            return None
        entry = dict(zip(ELB_LOG_COLUMNS, parts))
        # Parse and enrich 
        
        # Timestamp - convert to Eastern Time
        est_time = None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                dt_naive = datetime.strptime(entry["time"], fmt)
                dt_utc   = dt_naive.replace(tzinfo=timezone.utc)
                est_time = dt_utc.astimezone(EASTERN).isoformat()
                break
            except ValueError:
                continue
        if est_time is None: return None
        entry["time"] = est_time
        
        # Client IP
        client_ip = entry["client_ip_port"].split(":")[0]
        
        # Processing times 
        rpt = to_float(entry.get("request_processing_time", None))
        tpt = to_float(entry.get("target_processing_time", None))
        resppt = to_float(entry.get("response_processing_time", None))
        total_ms = None
        if None not in (rpt, tpt, resppt):
            total_ms = round((rpt + tpt + resppt) * 1000, 3)            
        # Request parse 
        try:
            method, full_url, version = entry["request"].split(" ", 2)
            up = urlparse(full_url)
            protocol     = up.scheme
            hostname     = up.hostname
            port_        = up.port
            path_        = up.path
            query_params = up.query
        except Exception:
            method, full_url, version = "Unknown", "", ""
            protocol = hostname = port_ = path_ = query_params = None
        # USER-AGEN -  get full then families
        ua_str = entry["user_agent"].strip('"')
        if ua_str and ua_str != "-":
            ua = ua_parse(ua_str)
            browser_family = ua.browser.family or "Unknown"
            os_family      = ua.os.family or "Unknown"
            is_bot_flag = any(t in ua_str.lower() for t in ["bot", "spider", "crawler", "python-urllib", "googlebot"])
        else:
            browser_family = os_family = "Unknown"
            is_bot_flag = False
        # --- Compose row ---
        row = dict(entry)
        row.update({
            "client_ip": client_ip,
            "http_method": method,
            "full_url": full_url,
            "http_version": version,
            "protocol": protocol,
            "hostname": hostname,
            "port": port_,
            "path": path_,
            "query_params": query_params,
            "total_processing_time_ms": total_ms,
            "ua_browser_family": browser_family,
            "ua_os_family": os_family,
            "is_bot": is_bot_flag,
            "log_source_file": source_file
        })
        return row
    except Exception:
        return None
    
def transform_elb_logs(bucket: str, keys: list):
    records = []
    for key in keys:
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
        with gzip.GzipFile(fileobj=BytesIO(body)) as gz:
            for raw_line in gz:
                line = raw_line.decode("utf-8").strip()
                parsed = parse_log_entry(line, key)
                if parsed:
                    records.append(parsed)
    df = pd.DataFrame(records)
    return df


def main():
    # Extract log files from S3
    print(f"\nListing ELB log files in s3://{AWS_BUCKET_NAME}/{AWS_LOG_PREFIX}")
    keys = extract_log_keys(AWS_BUCKET_NAME, AWS_LOG_PREFIX)
    if not keys:
        print("No .gz files found. Exiting.")
        return
    print(f"Found {len(keys)} ELB log file(s).")
    
    # Transform & Parse elb logs
    df_list = []
    for key in keys:
        print(f"Parsing: s3://{AWS_BUCKET_NAME}/{key}")
        df_parsed = transform_elb_logs(AWS_BUCKET_NAME, [key])
        print(f"Parsed {len(df_parsed)} records from {key}")
        df_list.append(df_parsed)
        print(f"Total records so far: {len(df_list)}")
    df_all = pd.concat(df_list, ignore_index=True)
    print(f"Total records after parsing: {len(df_all)}")

    # Show a sample of parsed rows in JSON
    print("\nSample data (JSON, first 5 rows):")
    print(df_all.head(5).to_json(orient="records", lines=True))
    
    
    # Enrich with geolocation data
    
    # Feature engineering / add advanced features
    
    # Load cleaned & enriched logs partitioned by year/month/day/countryCode
    
    
    
    
   
    