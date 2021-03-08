#!/usr/bin/env python3

import argparse
import logging
import netifaces
import os
import stat
import sys
import itertools

import gevent
import gevent.socket

from contestro import ServiceCoord, ConfigError, async_config, config


logger = logging.getLogger(__name__)


def get_service_address(key):
    if key in async_config.core_services:
        return async_config.core_services[key]
    else:
        raise KeyError('Service not found.')


def mkdir(path):
    '''Make directory without raising errors.'''
    try:
        os.mkdir(path)
    except FileExistsError:
        return True
    except OSError:
        return False

    return True


def get_safe_shards(service, shard):
    if shard is None:
        addrs = _find_local_addresses()
        computed_shard = _get_shard_from_addresses(service, addrs)
        if computed_shard is None:
            logger.critical("Couldn't autodetect shard number and "
                            "no shard specified for service %s, "
                            "quitting.", service)
            raise ValueError("No safe shard found for %s." % service)
        else:
            return computed_shard
    else:
        coord = ServiceCoord(service, shard)
        if coord not in async_config.core_services:
            logger.critical("The provided shard number for service %s "
                            "cannot be found in the configuration, "
                            "quitting.", service)
            raise ValueError("No safe shard found for %s." % service)
        else:
            return shard


def _get_shard_from_addresses(service, addrs):
    ipv4_addrs = set()
    ipv6_addrs = set()
    for proto, addr in addrs:
        if proto == gevent.socket.AF_INET:
            ipv4_addrs.add(addr)
        elif proto == gevent.socket.AF_INET6:
            ipv6_addrs.add(addr)

    for shard in itertools.count():
        try:
            host, port = get_service_address(ServiceCoord(service, shard))
        except KeyError:
            # No more shards to test.
            return None

        try:
            res_ipv4_addrs = set([x[4][0] for x in
                                  gevent.socket.getaddrinfo(
                                      host, port,
                                      gevent.socket.AF_INET,
                                      gevent.socket.SOCK_STREAM)])
        except OSError:
            pass
        else:
            if not ipv4_addrs.isdisjoint(res_ipv4_addrs):
                return shard

        try:
            res_ipv6_addrs = set([x[4][0] for x in
                                  gevent.socket.getaddrinfo(
                                      host, port,
                                      gevent.socket.AF_INET6,
                                      gevent.socket.SOCK_STREAM)])
        except OSError:
            pass
        else:
            if not ipv6_addrs.isdisjoint(res_ipv6_addrs):
                return shard


def _find_local_addresses():
    addrs = []

    for iface_name in netifaces.interfaces():
        for proto in [netifaces.AF_INET, netifaces.AF_INET6]:
            addrs += [
                (proto, i['addr']) for i in netifaces.ifaddresses(iface_name).
                setdefault(proto, [])
            ]

    return addrs


def default_argument_parser(description, cls):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('shard', action='store', type=int, nargs='?')

    args = parser.parse_args()

    try:
        args.shard = get_safe_shards(cls.__name__, args.shard)
    except ValueError:
        raise ConfigError("Couldn't autodetect shard number and "
                          "no shard specified for service %s, "
                          "quitting." % (cls.__name__,))

    return cls(args.shard)
