import json
import os
import base64
import hashlib
import hmac
import requests
from threading import Thread
import logging
import datetime as dt
import re
from datetime import timedelta
import azure.functions as func

# Sentinel configuration
sentinel_customer_id = os.environ.get('WorkspaceID')
sentinel_shared_key = os.environ.get('WorkspaceKey')
sentinel_log_type = os.environ.get('LogAnalyticsCustomLogName')
logAnalyticsUri = os.environ.get('LAURI')

# Trellix / MVISION ePO configuration
mvision_epo_token_url = os.environ.get('MVision_ePO_Token_Url')
mvision_epo_events_url = os.environ.get('MVision_ePO_Events_Url')
mvision_epo_client_id = os.environ.get('MVision_ClientID')
mvision_epo_password = os.environ.get('MVision_ePO_Password')        # used as client secret
mvision_epo_scope = os.environ.get('MVision_Scope')
mvision_epo_event_type = os.environ.get('MVision_EventType')
mvision_epo_event_limit = int(os.environ.get('MVision_EventsLimit') or 100)
mvision_epo_events_last_x_mins = int(os.environ.get('MVision_Events_Last_X_Mins') or 5)

if not logAnalyticsUri or str(logAnalyticsUri).isspace():
    logAnalyticsUri = f'https://{sentinel_customer_id}.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
if not re.match(pattern, logAnalyticsUri):
    raise Exception("Invalid Log Analytics Uri.")

def main(mytimer: func.TimerRequest) -> None:
    if mytimer.past_due:
        logging.warning('The timer is past due!')

    logging.info('Starting McAfee MVISION ePO Collector')

    connector = McAfeeEPO(
        token_url=mvision_epo_token_url,
        events_url=mvision_epo_events_url,
        client_id=mvision_epo_client_id,
        client_secret=mvision_epo_password,
        scope=mvision_epo_scope
    )

    ts_from, ts_to = connector.get_time_interval()
    logging.info(f'Retrieving events from {ts_from} to {ts_to}')

    events = connector.get_events(ts_from, ts_to, mvision_epo_event_type, mvision_epo_event_limit)

    if not events:
        logging.info('No events returned.')
        return

    total = 0
    failed = 0
    sent = 0

    for ev in events.get('data', []):
        sentinel = AzureSentinelConnector(
            logAnalyticsUri,
            sentinel_customer_id,
            sentinel_shared_key,
            sentinel_log_type,
            queue_size=10000,
            bulks_number=10
        )

        payload = {
            'sourcetype': events.get("type", "MVISION_EPO_Event"),
            **ev
        }

        with sentinel:
            sentinel.send(payload)

        total += 1
        failed += sentinel.failed_sent_events_number
        sent += sentinel.successfull_sent_events_number

    logging.info(f'{sent} events sent, {failed} failed out of {total} total.')

class McAfeeEPO:
    def __init__(self, token_url, events_url, client_id, client_secret, scope):
        self.token_url = token_url
        self.base = events_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json'})
        self.authenticate()

    def authenticate(self):
        """
        Use OAuth2 Client Credentials for token (recommended for Trellix/MVISION APIs). :contentReference[oaicite:2]{index=2}
        """
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope
        }

        try:
            res = requests.post(self.token_url, data=data, timeout=15)
            res.raise_for_status()
        except requests.RequestException as e:
            logging.error(f'Error getting token: {e}')
            raise

        token = res.json().get('access_token')
        if not token:
            logging.error("No access_token in response.")
            raise Exception("Authentication failed")

        self.session.headers.update({'Authorization': f'Bearer {token}'})
        logging.info('Authenticated to Trellix/MVISION ePO successfully.')

    def get_time_interval(self):
        now = dt.datetime.utcnow()
        past = now - timedelta(minutes=mvision_epo_events_last_x_mins)
        return past.strftime("%Y-%m-%dT%H:%M:%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ")

    def get_events(self, since, until, event_type, limit):
        params = {
            'type': event_type,
            'since': since,
            'until': until,
            'limit': limit
        }
        url = f'{self.base}/eventservice/api/v2/events'
        try:
            res = self.session.get(url, params=params, timeout=15)
            res.raise_for_status()
            logging.info('Successfully retrieved events.')
            return res.json()
        except requests.RequestException as e:
            logging.error(f'Failed retrieving events: {e}')
            return None

# Azure Sentinel ingestion class unchanged
class AzureSentinelConnector:
    def __init__(self, log_analytics_uri, customer_id, shared_key, log_type, queue_size=200, bulks_number=10, queue_size_bytes=25 * (2**20)):
        self.log_analytics_uri = log_analytics_uri
        self.customer_id = customer_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.queue_size = queue_size
        self.bulks_number = bulks_number
        self.queue_size_bytes = queue_size_bytes
        self._queue = []
        self._bulks_list = []
        self.successfull_sent_events_number = 0
        self.failed_sent_events_number = 0

    def send(self, event):
        self._queue.append(event)
        if len(self._queue) >= self.queue_size:
            self.flush(force=False)

    def flush(self, force=True):
        self._bulks_list.append(self._queue)
        if force or len(self._bulks_list) >= self.bulks_number:
            self._flush_bulks()
        self._queue = []

    def _flush_bulks(self):
        jobs = []
        for queue in self._bulks_list:
            if queue:
                for q in self._split_big_request(queue):
                    jobs.append(Thread(target=self._post_data, args=(self.customer_id, self.shared_key, q, self.log_type)))
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
        self._bulks_list = []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.flush()

    def _build_signature(self, customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, string_to_hash.encode('utf-8'), digestmod=hashlib.sha256).digest()).decode()
        return f"SharedKey {customer_id}:{encoded_hash}"

    def _post_data(self, customer_id, shared_key, body, log_type):
        body_str = json.dumps(body)
        rfc1123date = dt.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        signature = self._build_signature(customer_id, shared_key, rfc1123date, len(body_str), 'POST', 'application/json', '/api/logs')
        uri = f"{self.log_analytics_uri}/api/logs?api-version=2016-04-01"
        headers = {
            'content-type': 'application/json',
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }
        res = requests.post(uri, data=body_str, headers=headers)
        if 200 <= res.status_code < 300:
            self.successfull_sent_events_number += len(body)
        else:
            self.failed_sent_events_number += len(body)

    def _check_size(self, queue):
        return len(json.dumps(queue).encode()) < self.queue_size_bytes

    def _split_big_request(self, queue):
        if self._check_size(queue):
            return [queue]
        half = len(queue)//2
        return self._split_big_request(queue[:half]) + self._split_big_request(queue[half:])
