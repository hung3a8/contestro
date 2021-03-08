#!/usr/bin/env python3

import logging
import os
import time
from collections import deque

from contestro import config, mkdir
from contestro.io import Service, rpc_method
from contestro.log import root_logger, shell_handler, FileHandler, \
    DetailedFormatter


logger = logging.getLogger(__name__)


class LogService(Service):
    LAST_MESSAGE_COUNT = 100

    def __init__(self, shard):
        Service.__init__(self, shard)

        log_dir = os.path.join(config.log_dir, 'contestro')
        if not mkdir(config.log_dir) or not mkdir(log_dir):
            logger.error('Cannot create log directories.')
            self.exit()
            return

        if config.clear_old_logs:
            for old_log in os.listdir(log_dir):
                os.remove(os.path.join(log_dir, old_log))

        log_filename = '%d.log' % int(time.time())

        self.file_handler = FileHandler(os.path.join(log_dir, log_filename),
                                        mode='w', encoding='utf-8')

        self.file_handler.setLevel(logging.DEBUG)
        self.file_handler.setFormatter(DetailedFormatter(False))
        root_logger.addHandler(self.file_handler)

        try:
            os.remove(os.path.join(log_dir, 'last.log'))
        except OSError:
            pass

        os.symlink(log_filename, os.path.join(log_dir, 'last.log'))

        self._last_messages = deque(maxlen=self.LAST_MESSAGE_COUNT)

    @rpc_method
    def Log(self, **kwargs):
        record = logging.makeLogRecord(kwargs)

        shell_handler.handle(record)
        self.file_handler.handle(record)

        if record.levelno >= logging.WARNING:
            if hasattr(record, 'service_name') and \
                    hasattr(record, 'service_shard'):
                coord = '%s,%s' % (record.service_name, record.service_shard)
            else:
                coord = ''
            self._last_messages.append({
                'message': record.msg,
                'coord': coord,
                'operation': getattr(record, 'operation', ''),
                'severity': record.levelname,
                'timestamp': record.created,
                'exc_text': getattr(record, 'exc_text', None)
            })

    @rpc_method
    def last_messages(self):
        return list(self.last_messages)
