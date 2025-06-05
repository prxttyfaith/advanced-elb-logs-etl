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

def main():
    print(f"\nListing ELB log files in s3://{AWS_BUCKET_NAME}/{AWS_LOG_PREFIX}")
    # Extract log files from S3
    keys = extract_log_keys(AWS_BUCKET_NAME, AWS_LOG_PREFIX)
    print(f"Found {len(keys)} ELB log file(s).")
    
    # Transform & Parse elb logs
    
    # Show a sample of parsed rows in both JSON and table view
    
    # Enrich with geolocation data
    
    # Feature engineering / add advanced features
    
    # Load cleaned & enriched logs partitioned by year/month/day/countryCode
    
    
    
    
   
    