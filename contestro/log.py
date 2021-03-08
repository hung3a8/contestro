#!/usr/bin/env python3

import logging
import sys

import gevent.lock

from contestro_common.terminal import colors, add_color_to_string, \
    has_color_support


class StreamHandler(logging.StreamHandler):
    def createLock(self):
        self.lock = gevent.lock.RLock()


class FileHandler(logging.FileHandler):
    def createLock(self):
        self.lock = gevent.lock.RLock()


class LogServiceHandler(logging.Handler):
    def __init__(self, log_service):
        logging.Handler.__init__(self)
        self._log_service = log_service

    def createLock(self):
        self.lock = gevent.lock.RLock()

    def emit(self, record):
        try:
            exc_info = record.exc_info
            if exc_info:
                self.format(record)
                record.exc_info = None
            d = dict(record.__dict__)
            d['msg'] = record.getMessage()
            d['args'] = None
            if exc_info:
                record.exc_info = exc_info
            self._log_service.Log(**d)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handleError(record)


def get_color_hash(string):
    return [colors.BLACK,
            colors.RED,
            colors.GREEN,
            colors.YELLOW,
            colors.BLUE,
            colors.MAGENTA,
            colors.CYAN,
            colors.WHITE][hash(string) % 8]


class CustomFormatter(logging.Formatter):
    SEVERITY_COLORS = {logging.CRITICAL: colors.RED,
                       logging.ERROR: colors.RED,
                       logging.WARNING: colors.YELLOW,
                       logging.INFO: colors.GREEN,
                       logging.DEBUG: colors.CYAN}

    def __init__(self, colors=False):
        logging.Formatter.__init__(self, "")
        self.colors = colors

    def format(self, record: logging.LogRecord):
        record.message = record.getMessage()
        record.asctime = self.formatTime(record, self.datefmt)
        s = self.do_format(record)

        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            if s[-1:] != '\n':
                s = s + '\n'
            try:
                s = s + record.exc_text
            except UnicodeError:
                s = s + record.exc_text.decode(sys.getfilesystemencoding(),
                                               'replace')

        return s

    def do_format(self, record):
        severity = self.get_severity(record)
        coordinates = self.get_coordinates(record)
        operation = self.get_operation(record)
        message = record.message
        if self.colors:
            severity_col = self.SEVERITY_COLORS[record.levelno]
            severity = add_color_to_string(severity, severity_col,
                                           bold=True, force=True)
            coordinates_col = get_color_hash(coordinates)
            if len(coordinates) > 0:
                coordinates = add_color_to_string(coordinates, coordinates_col,
                                                  bold=True, force=True)
            operation_col = get_color_hash(operation)
            if len(operation) > 0:
                operation = add_color_to_string(operation, operation_col,
                                                bold=True, force=True)

        fmt = severity
        if coordinates.strip() != "":
            fmt += " [%s]" % (coordinates.strip())
        if operation.strip() != "":
            fmt += " [%s]" % (operation.strip())
        fmt += " %s" % message
        return fmt

    def get_severity(self, record):
        severity = record.asctime + ' - ' + record.levelname
        return severity

    def get_coordinates(self, record):
        if hasattr(record, 'service_name') and \
                hasattr(record, 'service_shard'):
            service = record.service_name\
                .replace('Service', '')
            coordinates = '%s,%d' % (service, record.service_shard)
        else:
            coordinates = '<Unknown>'
        return coordinates

    def get_operation(self, record):
        return record.operation if hasattr(record, 'operation') else ''


class DetailedFormatter(CustomFormatter):
    def get_coordinates(self, record):
        coordinates = super().get_coordinates(record)
        coordinates += '%s' % (
            record.threadName.replace('Thread', '').replace('Dummy-', ''))

        coordinates += '%s::%s' % (
            record.filename.replace('.py', ''), record.funcName)

        return coordinates


class ServiceFilter(logging.Filter):
    def __init__(self, name, shard):
        logging.Filter.__init__(self, '')
        self.name = name
        self.shard = shard

    def filter(self, record):
        if not hasattr(record, "service_name") or \
                not hasattr(record, "service_shard"):
            record.service_name = self.name
            record.service_shard = self.shard
        return True


class OperationAdapter(logging.LoggerAdapter):
    def __init__(self, logger, operation):
        logging.LoggerAdapter.__init__(self, logger, {'operation': operation})
        self.operation = operation

    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {}).setdefault("operation", self.operation)
        return msg, kwargs


root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

shell_handler = StreamHandler(sys.stdout)
shell_handler.setLevel(logging.INFO)
shell_handler.setFormatter(CustomFormatter(has_color_support(sys.stdout)))
root_logger.addHandler(shell_handler)


def set_detailed_logs(detailed):
    global shell_handler
    color = has_color_support(sys.stdout)
    formatter = DetailedFormatter(color) if detailed else \
        CustomFormatter(color)
    shell_handler.setFormatter(formatter)
