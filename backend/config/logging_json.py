from json_log_formatter import JSONFormatter

class CustomJsonFormatter(JSONFormatter):
    def json_record(self, message, extra, record):
        extra['level'] = record.levelname
        extra['logger'] = record.name
        extra['trace_id'] = getattr(record, 'trace_id', '-')
        return super().json_record(message, extra, record)