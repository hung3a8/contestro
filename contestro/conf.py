#!/usr/bin/env python3

import errno
import configparser
import io
import logging
import os
import sys
import getpass
from collections import namedtuple

from .log import set_detailed_logs


logger = logging.getLogger(__name__)


class ServiceCoord(namedtuple("ServiceCoord", "name shard")):
    def __repr__(self):
        return "%s,%d" % (self.name, self.shard)


class Address(namedtuple("Address", "ip port")):
    def __repr__(self):
        return "%s:%d" % (self.ip, self.port)


class ConfigError(Exception):
    pass


class AsyncConfig:
    core_services = {}


async_config = AsyncConfig()


class Config():
    def __init__(self):
        self.async_config = async_config

        # System-wide
        self.log_level_debug = False

        # ContestServer.
        self.contest_listen_address = 'localhost'
        self.contest_listen_port = 8888
        self.max_submission_file_size = 512000  # 500KB
        self.submission_limit = 1  # for each tasks

        # AdminServer
        self.admin_listen_address = ''
        self.admin_listen_port = 8889

        # LogService
        self.max_log_length = 5120  # 5KB
        self.log_dir = os.path.join('/', 'home', 'contestro', 'log')
        self.clear_old_logs = False

        # Check if Contestro is installed
        paths = [
            '/usr/local/etc/contestro.conf',
            './config/contestro.conf'
        ]

        self._load(paths)

        set_detailed_logs(self.log_level_debug)

    def _load(self, paths):
        for path in paths:
            if self.load_unique(path):
                logger.info('Using configuration file %s.', path)
                return

        logger.warning('Cannot parse any configuration files.')

    def load_unique(self, path):
        config = configparser.ConfigParser(allow_no_value=True,
                                           inline_comment_prefixes=('#', ';'))
        config.optionxform = str

        try:
            config.read(path)
        except IOError as error:
            if error.errno == errno.ENOENT:
                logger.debug('Couldn\'t find config file %s.', path)
            else:
                logger.warning('Unexpected error while opening the file %s: '
                               '[%s] %s',
                               path, errno.errorcode[error.errno],
                               error
                               )
        except configparser.MissingSectionHeaderError as error:
            logger.warning('Couldn\'t read config file %s: %s.', path, error)
            return False

        for service in config['core_services']:
            for shard_number, shard in \
                    enumerate(eval(config['core_services'][service])):
                coord = ServiceCoord(service, shard_number)
                self.async_config.core_services[coord] = Address(*shard)

        for other_config in config:
            if other_config == 'core_services':
                continue
            for config_name in config[other_config]:
                try:
                    if hasattr(self, config_name):
                        setattr(self, config_name,
                                eval(config[other_config][config_name]))
                    else:
                        logger.warning('No attribute name %s.', config_name)
                        return False
                except ValueError:
                    logger.warning('Unexpected value of %s: %s.',
                                   config_name,
                                   config[other_config][config_name])
                    return False

        return True


config = Config()
