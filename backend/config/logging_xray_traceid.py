from aws_xray_sdk.core import xray_recorder
import logging

class XRayTraceIdFilter(logging.Filter):
    def filter(self, record):
        try:
            record.trace_id = xray_recorder.current_trace_id() or "-"
        except Exception:
            record.trace_id = "-"
        return True
