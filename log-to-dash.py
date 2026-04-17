import logging
import time
def security_event_logging(username, role, resource, ip, mfaResult, serviceAccessResult, reasonForResult):
    logging.basicConfig(filename='security_events_tracking.txt', level=logging.INFO)
    logging.info('Security Events Tracking Started\n\n')
    login_entry = {
        'event_type': 'Login attempt',
        'username': username,
        'ip': ip,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        'role': role,
        'resource': resource,
    }
    logging.info(login_entry)
    logging.info('\n')
    mfa_entry = {
        'event_type': 'MFA',
        'username': username,
        'ip': ip,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        'role': role,
        'resource': resource,
        'result': mfaResult,
    }
    if mfaResult != 'Denied':
        logging.info(mfa_entry)
        logging.info('\n')
        access_entry = {
            'event_type': 'Access attempt',
            'username': username,
            'ip': ip,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            'role': role,
            'resource': resource,
            'result': serviceAccessResult,
            'reason': reasonForResult,
        }
        if access_entry['role'] == access_entry['resource']:
            logging.info(access_entry)
        else:
            logging.warning(access_entry)
        logging.info('\n')

if __name__ == '__main__':
    security_event_logging(
        username='alice',
        role='admin',
        resource='server1',
        ip='192.168.1.1',
        mfaResult='Approved',
        serviceAccessResult='Approved',
        reasonForResult='N/A'
    )
    with open('security_events_tracking.txt', 'r') as file:
        for line in file:
            print(line.strip())
    with open('security_events_tracking.txt', 'w') as file:
        pass
'''
import logging
import structlog
import time


from opentelemetry import _logs
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry._logs import set_logger_provider

# -----------------------------
# OpenTelemetry setup
# -----------------------------
logger_provider = LoggerProvider()
set_logger_provider(logger_provider)   # ✅ IMPORTANT FIX

exporter = OTLPLogExporter(
    endpoint="http://localhost:4318/v1/logs"
)

logger_provider.add_log_record_processor(
    BatchLogRecordProcessor(exporter)
)

otel_handler = LoggingHandler(
    level=logging.INFO,
    logger_provider=logger_provider
)
'''

# -----------------------------
# Standard logging
# -----------------------------
'''
logging.basicConfig(
    level=logging.INFO,
    handlers=[otel_handler]
)
'''
# -----------------------------
# structlog config
# -----------------------------
'''
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

log = structlog.get_logger()

# -----------------------------
# TEST LOGS
# -----------------------------
log.info("login_attempt", username="alice", success=True)
log.warning("mfa_failure", username="bob")
log.error("unauthorized_access", ip="192.168.1.1")
'''
#print("Sending logs...")
#time.sleep(10)  # Allow time for logs to be sent

# -----------------------------
# FORCE FLUSH (CRITICAL)
# -----------------------------
#logger_provider.shutdown()