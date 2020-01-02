#!/usr/bin/env python

import argparse
import json
import sys
import os
import signal
import collections
import ipaddress

import yaml
from plumbum import FG
from plumbum import local
from plumbum.cmd import aws
from plumbum.cmd import psql
from plumbum.cmd import dig
from plumbum.cmd import mysql
from plumbum.cmd import influx

rediscli = local['redis-cli']

AWS_TYPE_REDSHIFT = 'redshift'
AWS_TYPE_RDS_POSTGRES = 'rds-postgres'
AWS_TYPE_RDS_MYSQL = 'rds-mysql'
AWS_TYPE_ELASTICACHE_REDIS = 'elasticache-redis'
AWS_TYPE_INFLUXDB = 'influxdb'

class NotPrivateIpError(Exception):
    pass

# https://stackoverflow.com/questions/9306100/how-can-i-tell-if-a-child-is-asking-for-stdin-how-do-i-tell-it-to-stop-that
# https://stackoverflow.com/questions/15200700/how-do-i-set-the-terminal-foreground-process-group-for-a-process-im-running-und
# http://curiousthing.org/sigttin-sigttou-deep-dive-linux
"""

SIGTTIN is the Kernel’s way of telling Python that it won’t get input just now because it’s not in the foreground. If Python is brought back to the foreground, the shell would send a SIGCONT signal to instruct Python to resume (and Python would have to retry read()-ing).

SIGTTOU does something similar, but for writes. However, note that “writing” to the TTY can mean either of two things:

    Writing to stdout or stderr.
    Changing terminal settings.
"""
def become_fg_process_group():
    # we are going to get SIGTTOU because terminal settings change, which would put us to sleep
    hdlr = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    os.setpgrp()  # create a new process group so the newly started process can get ctrl-c,z
    tty = os.open('/dev/tty', os.O_RDWR)
    os.tcsetpgrp(tty, os.getpgrp())  # make the process group foreground for the tty
    os.close(tty)
    signal.signal(signal.SIGTTOU, hdlr)  # restore normal signal handling

def get_environ(cmd):
    if hasattr(cmd, 'envvars'):
        return cmd.envvars
    if hasattr(cmd, 'cmd'):
        return get_environ(cmd.cmd)
    # couldn't find anything
    return {}

def format_cmd(cmd):
    # TODO add environment vars with shlex.quote
    environ = get_environ(cmd)
    environ_str = ''
    for k,v in environ.items():
        environ_str += '{}={} '.format(k,v)
    return environ_str + str(cmd)

def run_fg(cmd):
    print('running:', format_cmd(cmd))
    cmd(stdin=None, stdout=None, stderr=None, preexec_fn=become_fg_process_group)

def build_alias_lookup_table(credentials):
    tbl = dict()
    for db_identifier in credentials:
        aliases = credentials[db_identifier]['aliases']
        for alias in aliases:
            if alias in tbl:
                print('error: duplicated alias', alias)
                sys.exit(1)
            tbl[alias] = db_identifier
    return tbl

def get_redshift_private_ip_port(aws_identifier):
    out = aws['redshift', 'describe-clusters', '--cluster-identifier', aws_identifier]()
    reply = json.loads(out)
    clusters = reply['Clusters']
    if len(clusters) != 1:
        print('unexpected clusters result')
        sys.exit(1)
    cluster = clusters[0]
    for node in cluster['ClusterNodes']:
        if node['NodeRole'] != 'LEADER':
            continue
        return node['PrivateIPAddress'], cluster['Endpoint']['Port']
    print('leader node ip addr not found')
    sys.exit(1)

def resolve_dns(dns, dns_servers):
    private_ip = dig['+short', '@' + dns_servers, dns]()
    private_ip = private_ip.strip().split('\n')[-1]

    return private_ip

def get_rds_private_ip_port(aws_identifier, dns_servers):

    out = aws['rds', 'describe-db-instances', '--db-instance-identifier', aws_identifier]()
    reply = json.loads(out)

    # pp reply['DBInstances'][0]['Endpoint']
    # {'Address': 'prod-rds-unicorn.cujpo2r0mujo.us-east-1.rds.amazonaws.com',
    # 'HostedZoneId': 'Z2R2ITUGPM61AM',
    # 'Port': 5432}

    endpoint = reply['DBInstances'][0]['Endpoint']
    dns = endpoint['Address']
    port = endpoint['Port']
    private_ip = resolve_dns(dns, dns_servers)
    return private_ip, port

def get_elasticache_clusters():
    rc, out, err = aws['elasticache', 'describe-cache-clusters', '--show-cache-node-info'].run(retcode=None)
    if rc:
        raise RuntimeError(rc, out, err)
    reply = json.loads(out)['CacheClusters']
    return reply

def get_elasticache_private_ip_port(aws_identifier, dns_servers, cache_node_id):
    # aws elasticache describe-replication-groups
    # aws elasticache describe-cache-clusters --show-cache-node-info # single node clusters


    clusters = get_elasticache_clusters()

    for cluster in clusters:
        replication_group_id = cluster.get('ReplicationGroupId', '')
        cache_cluster_id = cluster.get('CacheClusterId', '')
        cache_nodes = cluster['CacheNodes']
        # if aws_identifier == replication_group_id or aws_identifier == cache_cluster_id:
        if aws_identifier == cache_cluster_id:
            break
    else:
        cache_cluster_ids = [ cluster['CacheClusterId'] for cluster in clusters ]
        cache_cluster_ids = sorted(cache_cluster_ids)
        raise RuntimeError('{} not found in elasticache {}'.format(aws_identifier, cache_cluster_ids))


    for cache_node in cache_nodes:
        aws_cache_node_id = cache_node['CacheNodeId']
        if aws_cache_node_id == cache_node_id:
            break
    else:
        raise RuntimeError('chache node id {} not found in {}'.format(cache_node_id, cache_nodes))

    dns = cache_node['Endpoint']['Address']
    port = cache_node['Endpoint']['Port']
    private_ip = resolve_dns(dns, dns_servers)
    if not ipaddress.ip_address(private_ip).is_private:
        raise NotPrivateIpError('ip {} is not private'.format(private_ip))
    return private_ip, port

def load_config():
    config_locations = [
        os.path.expanduser('~/.medusarc'),
        '/etc/medusarc',
    ]
    for path in config_locations:
        try:
            with open(path) as f:
                config = yaml.safe_load(f)
            return config['datastores'], config['settings']
        except FileNotFoundError:
            pass
    raise RuntimeError('no config found in any of {}'.format(config_locations))

def get_user(argv, db_identifier, credentials):
    db_users = list(credentials[db_identifier]['users'].keys())
    if not len(argv):
        print('expected db user, allowed values for {} are {}'.format(db_identifier, db_users))
        sys.exit(1)

    db_user = argv.pop(0)
    if db_user not in db_users:
        print('expected db user, allowed values for {} are {}'.format(db_identifier, db_users))
        sys.exit(1)

    db_password = credentials[db_identifier]['users'][db_user]

    return db_user, db_password

def get_db(argv, db_identifier, credentials):
    db_names = credentials[db_identifier]['databases']
    db_names = map(str, credentials[db_identifier]['databases'])  # ensure db names are strings
    db_names = sorted(db_names)
    if not len(argv):
        print('expected db name, allowed values for {} are {}'.format(db_identifier, db_names))
        sys.exit(1)

    db_name = argv.pop(0)
    if db_name not in db_names:
        print('expected db name, allowed values for {} are {}'.format(db_identifier, db_names))
        sys.exit(1)

    return db_name

def print_db_identifiers(db_identifiers):
    for ident in db_identifiers:
        print(' ', ident)

def get_db_identifier(argv, db_aliases, credentials):
    db_identifiers = sorted(db_aliases.keys())
    if not len(argv):
        print('expected db identifier, allowed values are:')
        print_db_identifiers(db_identifiers)
        sys.exit(1)

    db_identifier = argv.pop(0)
    if db_identifier not in db_identifiers:
        print('expected db identifier, allowed values are:')
        print_db_identifiers(db_identifiers)
        sys.exit(1)

    db_identifier = db_aliases[db_identifier]
    return db_identifier

def get_cache_node_id(argv, db_identifier, credentials):
    cache_node_ids = credentials[db_identifier]['cache_node_ids']
    cache_node_ids = sorted(cache_node_ids)
    if not len(argv):
        print('expected cache node id, allowed values are {}'.format(cache_node_ids))
        sys.exit(1)

    cache_node_id = argv.pop(0)
    if cache_node_id not in cache_node_ids:
        print('expected cache node id, allowed values are {}'.format(cache_node_ids))
        sys.exit(1)

    return cache_node_id


def redshift_cmd(argv, db_identifier, credentials, dns_servers):
    db_user, db_password = get_user(argv, db_identifier, credentials)
    db_name = get_db(argv, db_identifier, credentials)

    aws_identifier = credentials[db_identifier]['aws_identifier']
    ip, port = get_redshift_private_ip_port(aws_identifier)

    psql_env = psql.setenv(PGPASSWORD=db_password)
    cmd = psql_env['-U', db_user, '-h', ip, '--port', port, db_name]
    return cmd

def postgres_cmd(argv, db_identifier, credentials, dns_servers):
    db_user, db_password = get_user(argv, db_identifier, credentials)
    db_name = get_db(argv, db_identifier, credentials)

    aws_identifier = credentials[db_identifier]['aws_identifier']
    ip, port = get_rds_private_ip_port(aws_identifier, dns_servers)

    psql_env = psql.setenv(PGPASSWORD=db_password)
    cmd = psql_env['-U', db_user, '-h', ip, '--port', port, db_name]
    return cmd

def mysql_cmd(argv, db_identifier, credentials, dns_servers):
    db_user, db_password = get_user(argv, db_identifier, credentials)
    db_name = get_db(argv, db_identifier, credentials)

    aws_identifier = credentials[db_identifier]['aws_identifier']
    ip, port = get_rds_private_ip_port(aws_identifier, dns_servers)

    password = '-p' + db_password
    cmd = mysql['-u', db_user, password, '-h', ip, '--port', port, db_name]
    return cmd

def redis_cmd(argv, db_identifier, credentials, dns_servers):
    db_name = get_db(argv, db_identifier, credentials)
    cache_node_id = get_cache_node_id(argv, db_identifier, credentials)

    aws_identifier = credentials[db_identifier]['aws_identifier']
    ip, port = get_elasticache_private_ip_port(aws_identifier, dns_servers, cache_node_id)

    cmd = rediscli['-h', ip, '-p', port, '-n', db_name]
    return cmd

def influx_cmd(argv, db_identifier, credentials, dns_servers):
    db_user, db_password = get_user(argv, db_identifier, credentials)
    db_name = get_db(argv, db_identifier, credentials)
    aws_identifier = credentials[db_identifier]['aws_identifier']
    private_ip = resolve_dns(aws_identifier, dns_servers)

    cmd = influx['-host', private_ip, '-database', db_name, '-username', db_user,
        '-password', db_password, '-precision', 'rfc3339']
    return cmd




aws_type_to_cmd = {
    AWS_TYPE_REDSHIFT: redshift_cmd,
    AWS_TYPE_RDS_POSTGRES: postgres_cmd,
    AWS_TYPE_RDS_MYSQL: mysql_cmd,
    AWS_TYPE_ELASTICACHE_REDIS: redis_cmd,
    AWS_TYPE_INFLUXDB: influx_cmd,
}



def main(argv=None):
    credentials, settings = load_config()

    # In EC2-VPC, the Amazon DNS server is located at the base of your VPC network range plus two
    # For example, the DNS Server on a 10.0.0.0/16 network is located at 10.0.0.2.
    # For VPCs with multiple IPv4 CIDR blocks, the DNS server IP address is located in the primary CIDR block.
    # too hard to resolve VPC subnet, hardcode
    dns_servers = settings['dns_servers']['us_prod']

    if not argv:
        argv = sys.argv
    cmd = argv.pop(0)

    # db_identifier, user, database change depending on passed value

    # TODO implement multi aws account support
    # TODO memcache support
    # TODO redis db aliases?
    # TODO implement partial prefix matches + check for ambiguous prefixes
    # TODO change sort in help output

    db_aliases = build_alias_lookup_table(credentials)

    db_identifier = get_db_identifier(argv, db_aliases, credentials)
    aws_type = credentials[db_identifier]['aws_type']
    cmd_fn = aws_type_to_cmd.get(aws_type)
    if not cmd_fn:
        print('unknown aws_type {}'.format(aws_type))
        sys.exit(1)
    cmd = cmd_fn(argv, db_identifier, credentials, dns_servers)

    run_fg(cmd)


if __name__ == '__main__':
    main()

# vim: set syntax=python
