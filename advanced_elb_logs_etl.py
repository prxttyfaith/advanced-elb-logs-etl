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

from logger import get_logger
logger = get_logger(__name__)

# AWS S3 Configuration
load_dotenv()
AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_BUCKET_NAME       = os.getenv("AWS_BUCKET_NAME")
AWS_LOG_PREFIX        = os.getenv("AWS_LOG_PREFIX", "")
AWS_REGION            = os.getenv("AWS_REGION", "us-west-2")

OUTPUT_CLEANED        = "output/cleaned_logs"
OUTPUT_AGG            = "output/aggregated_stats"
OUTPUT_REPORTS        = "output/reports"
GEO_CACHE_PATH        = os.path.join("output", "ip_geolocation_cache.parquet")
EASTERN               = pytz.timezone("America/New_York")

for folder in [OUTPUT_CLEANED, OUTPUT_AGG, OUTPUT_REPORTS, "output"]:
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
    try:
        paginator = s3.get_paginator('list_objects_v2')
        keys = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            keys += [obj['Key'] for obj in page.get('Contents', []) if obj['Key'].endswith('.gz')]
        logger.info(f"Extracted {len(keys)} log keys from S3 bucket {bucket}.")
        return keys
    except Exception as e:
        logger.error(f"Error extracting log keys: {e}")
        return []

def parse_log_entry(line: str, source_file: str):
    try:
        parts = shlex.split(line)
        if len(parts) < len(ELB_LOG_COLUMNS):
            return None
        entry = dict(zip(ELB_LOG_COLUMNS, parts))
        
        # PARSE AND ENRICH LOG ENTRY        
        # Timestamp - convert to Eastern Time
        est_time = None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                dt_naive = datetime.strptime(entry["time"], fmt)
                dt_utc   = dt_naive.replace(tzinfo=timezone.utc)
                est_time = dt_utc.astimezone(EASTERN)
                break
            except ValueError:
                continue
        if est_time is None: 
            logger.warning(f"Invalid timestamp in {source_file}: {entry['time']}")
            return None
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
    except Exception as e:
        logger.error(f"Error parsing log entry: {e}")
        return None
    
def transform_elb_logs(bucket: str, keys: list):
    try:
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
    except Exception as e:
        logger.error(f"Error transforming ELB logs: {e}")
        return pd.DataFrame()
        
# GEOLOCATION ENRICHMENT WITH CACHE 
def fetch_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,query"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 429:   # Rate limit
            time.sleep(1)
            return fetch_geolocation(ip)
        data = resp.json()
        if data.get('status') == 'success':
            data['api_fetch_timestamp'] = pd.Timestamp.now(tz='UTC')
            return data
        else:
            # On error, store minimal info for cache
            return {
                'status': 'fail',
                'message': data.get('message', 'API Error'),
                'query': ip,
                'country': None, 'countryCode': None, 'region': None, 'regionName': None,
                'city': None, 'lat': None, 'lon': None, 'isp': None, 'api_fetch_timestamp': pd.Timestamp.now(tz='UTC')
            }
    except Exception as e:
        logger.error(f"Error fetching geolocation for {ip}: {e}")
        return {
            'status': 'fail', 'message': str(e), 'query': ip, 'country': None, 'countryCode': None, 'region': None,
            'regionName': None, 'city': None, 'lat': None, 'lon': None, 'isp': None, 'api_fetch_timestamp': pd.Timestamp.now(tz='UTC')
        }

def load_geo_cache():
    # Ensure 'query' is in columns so set_index('query') never fails
    columns = [
        "status", "message", "country", "countryCode", "region", "regionName", "city",
        "lat", "lon", "isp", "query", "api_fetch_timestamp"
    ]
    try:
        if os.path.exists(GEO_CACHE_PATH):
            df = pd.read_parquet(GEO_CACHE_PATH)
            if not df.empty:
                # If 'query' already the index, just return it
                if df.index.name == "query":
                    return df
                elif "query" in df.columns:
                    return df.set_index("query")
                else:
                    # Defensive: create missing column if needed
                    df["query"] = None
                    return df.set_index("query")
            else:
                # empty file
                df = pd.DataFrame(columns=columns)
                return df.set_index("query")
        else:
            df = pd.DataFrame(columns=columns)
            return df.set_index("query")
    except Exception as e:
        logger.error(f"Error loading geolocation cache: {e}")
        return pd.DataFrame(columns=columns).set_index("query")

def enrich_with_geolocation(df_logs):
    # Load existing cache
    try:
        geo_cache = load_geo_cache()
        all_ips = df_logs["client_ip"].dropna().unique()
        new_ips = [ip for ip in all_ips if ip not in geo_cache.index]
        # Fetch new IPs
        new_geo_data = []
        for ip in new_ips:
            geo = fetch_geolocation(ip)
            new_geo_data.append(geo)
            time.sleep(0.7)
        if new_geo_data:
            df_new = pd.DataFrame(new_geo_data).set_index("query")
            geo_cache = pd.concat([geo_cache, df_new])
            geo_cache = geo_cache[~geo_cache.index.duplicated(keep='last')]
            geo_cache.reset_index().to_parquet(GEO_CACHE_PATH, index=False)
        # Merge
        geo_cache = geo_cache.reset_index()
        df_merged = pd.merge(df_logs, geo_cache, left_on="client_ip", right_on="query", how="left", suffixes=("", "_geo"))
        # Standardize columns for ease
        df_merged.rename(columns={
            'country': 'countryName',
            'countryCode': 'countryCode',
            'region': 'region',
            'regionName': 'regionName',
            'city': 'city',
            'lat': 'lat',
            'lon': 'lon',
            'isp': 'isp'
        }, inplace=True)
        return df_merged
    except Exception as e:
        logger.error(f"Error enriching logs with geolocation: {e}")
        return df_logs

#  ADVANCED FEATURE ENGINEERING 
def status_code_type(code):
    try:
        code = int(code)
        if 100 <= code < 200: return '1xx_Informational'
        if 200 <= code < 300: return '2xx_Success'
        if 300 <= code < 400: return '3xx_Redirection'
        if 400 <= code < 500: return '4xx_ClientError'
        if 500 <= code < 600: return '5xx_ServerError'
    except: pass
    return 'Unknown'

def add_advanced_features(df):
    try:
        # Remove rows missing critical fields
        df = df[~df['client_ip'].isna()]
        # Clean types
        df['elb_status_code'] = df['elb_status_code'].apply(to_int)
        df['target_status_code'] = df['target_status_code'].apply(to_int)
        df['received_bytes'] = df['received_bytes'].apply(to_int)
        df['sent_bytes'] = df['sent_bytes'].apply(to_int)
        df['total_processing_time_ms'] = df['total_processing_time_ms'].astype('float32')
        # Status type
        df['status_code_type'] = df['elb_status_code'].apply(status_code_type).astype('category')
        # Time-based features
        df["time"] = pd.to_datetime(df["time"])
        df['request_year'] = df['time'].dt.year.astype('int16')
        df['request_month'] = df['time'].dt.month.astype('int8')
        df['request_day'] = df['time'].dt.day.astype('int8')
        df['request_hour'] = df['time'].dt.hour.astype('int8')
        df['request_day_of_week'] = df['time'].dt.day_name()
        df['request_week_of_year'] = df['time'].dt.isocalendar().week.astype('int8')
        # Path features
        df['path_depth'] = df['path'].astype(str).str.count('/')
        df['path_main_segment'] = df['path'].astype(str).str.split('/').apply(lambda x: x[1] if len(x)>1 else None)
        # Sessionization (simplified)
        df = df.sort_values(['client_ip', 'time'])
        df['prev_time'] = df.groupby('client_ip')['time'].shift(1)
        df['time_diff_min'] = (df['time'] - df['prev_time']).dt.total_seconds().div(60)
        df['new_session'] = (df['time_diff_min'] > 30) | df['time_diff_min'].isna()
        df['session_id'] = (df.groupby('client_ip')['new_session']
                            .cumsum().astype('int32').astype(str)) + '-' + df['client_ip']
        # Rolling aggregations (windowed, advanced use: .transform on groupby)
        df['rolling_5min_req_count'] = (
            df.groupby('client_ip')
            .rolling('5T', on='time')['request'].count()
            .reset_index(level=0, drop=True)
        )
        df['rolling_1h_avg_proc_time'] = (
            df.groupby('client_ip')
            .rolling('60T', on='time')['total_processing_time_ms'].mean()
            .reset_index(level=0, drop=True)
        )
        return df
    except Exception as e:
        logger.error(f"Error adding advanced features: {e}")
        return df
    
# OUTPUT WRITING FUNCTIONS 
def write_cleaned_logs(df):
    try:
        # Partitioned by year, month, day, countryCode (as required)
        for (yr, mth, day, cc), group in df.groupby(['request_year', 'request_month', 'request_day', 'countryCode']):
            out_dir = os.path.join(
                OUTPUT_CLEANED,
                f"year={int(yr)}",
                f"month={int(mth):02d}",
                f"day={int(day):02d}",
                f"countryCode={cc if pd.notnull(cc) else 'UNK'}"
            )
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, "data.parquet")
            group = group.copy()
            group["time"] = group["time"].dt.strftime("%Y-%m-%d %H:%M:%S%z")
            group.dropna(axis=1, how='all').to_parquet(out_path, index=False)
    except Exception as e:
        logger.error(f"Error writing cleaned logs: {e}")
        
def write_hourly_aggregation(df):
    try: 
        agg = df.groupby([
            "request_year", "request_month", "request_day", "request_hour", "countryName", "city"
        ]).agg(
            request_count = ("client_ip", "count"),
            unique_client_ips_count = ("client_ip", "nunique"),
            average_total_processing_time = ("total_processing_time_ms", "mean"),
            median_total_processing_time = ("total_processing_time_ms", "median"),
            sum_sent_bytes = ("sent_bytes", "sum"),
            sum_received_bytes = ("received_bytes", "sum"),
            count_2xx = ("status_code_type", lambda x: (x == "2xx_Success").sum()),
            count_4xx = ("status_code_type", lambda x: (x == "4xx_ClientError").sum()),
            count_5xx = ("status_code_type", lambda x: (x == "5xx_ServerError").sum()),
        ).reset_index()
        out_path = os.path.join(OUTPUT_AGG, "hourly_traffic_by_geo.parquet")
        agg.to_parquet(out_path, index=False)
    except Exception as e:
        logger.error(f"Error writing hourly aggregation: {e}")
        
def write_error_report(df):
    try:
        err_df = df[df["status_code_type"].isin(["4xx_ClientError", "5xx_ServerError"])]
        cols = [
            "time", "client_ip", "city", "countryName", "isp",
            "http_method", "full_url", "elb_status_code", "target_status_code_list",
            "user_agent", "ua_browser_family", "ua_os_family", "error_reason"
        ]
        out_path = os.path.join(OUTPUT_REPORTS, "error_summary_geo.csv")
        err_df = err_df.copy()
        err_df["time"] = err_df["time"].dt.strftime("%Y-%m-%d %H:%M:%S%z")
        err_df[cols].to_csv(out_path, index=False)
    except Exception as e:
        logger.error(f"Error writing error report: {e}")

def write_bot_traffic_reports(df):
    try:
        bots = df[df["is_bot"] == True]
        bots = bots.copy()
        bots["time"] = bots["time"].dt.strftime("%Y-%m-%d %H:%M:%S%z")
        # Details parquet
        out_path = os.path.join(OUTPUT_REPORTS, "bot_traffic_details.parquet")
        bots.to_parquet(out_path, index=False)
        # Aggregated summary
        bot_agg = bots.groupby(["countryName", "isp"]).size().reset_index(name="bot_request_count")
        out_path2 = os.path.join(OUTPUT_REPORTS, "bot_traffic_by_origin_summary.csv")
        bot_agg.to_csv(out_path2, index=False)
    except Exception as e:
        logger.error(f"Error writing bot traffic reports: {e}")

def main():
    try:
        # Extract log files from S3
        logger.info(f"\nListing ELB log files in s3://{AWS_BUCKET_NAME}/{AWS_LOG_PREFIX}")
        keys = extract_log_keys(AWS_BUCKET_NAME, AWS_LOG_PREFIX)
        if not keys:
            logger.warning("No .gz files found. Exiting.")
            return
        logger.info(f"Found {len(keys)} ELB log file(s).")
        
        # Transform & Parse elb logs
        df_list = []
        for key in keys:
            logger.info(f"Parsing: s3://{AWS_BUCKET_NAME}/{key}")
            df_parsed = transform_elb_logs(AWS_BUCKET_NAME, [key])
            logger.info(f"Parsed {len(df_parsed)} records from {key}")
            df_list.append(df_parsed)
            logger.info(f"Total records so far: {len(df_list)}")
        df_all = pd.concat(df_list, ignore_index=True)
        logger.info(f"Total records after parsing: {len(df_all)}")

        # Show a sample of parsed rows in JSON
        logger.info(f"\nSample data (JSON, first 5 rows):")
        logger.info(df_all.head(5).to_json(orient="records", lines=True))
        
        # Enrich with geolocation data
        logger.info("\nEnriching logs with geolocation data ...")
        df_enriched = enrich_with_geolocation(df_all)
        
        # Feature engineering / add advanced features
        logger.info("Adding advanced features ...")
        df_final = add_advanced_features(df_enriched)
        
        logger.info("Writing cleaned & enriched logs partitioned by year/month/day/countryCode ...")
        write_cleaned_logs(df_final)
        
        logger.info("Writing hourly traffic aggregation ...")
        write_hourly_aggregation(df_final)
        
        logger.info("Writing error summary report ...")
        write_error_report(df_final)
        
        logger.info("Writing bot traffic analysis reports ...")
        write_bot_traffic_reports(df_final)
        
        logger.info("\nAll done!\n")
    except Exception as e:
        logger.error(f"An error occurred in the main ETL process: {e}")

if __name__ == "__main__":
    main()