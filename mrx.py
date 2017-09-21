#!/usr/bin/env python
""" mrx: mass remote execute """
from __future__ import print_function
from __future__ import division
import argparse
from getpass import getpass
import logging
import os
import random
import sys
import threading
from threading import Thread, active_count
from time import ctime, sleep
from term import incolor
from std import NonBlockingConsole

import pexpect
from pexpect import pxssh, EOF, TIMEOUT
from pexpect.pxssh import ExceptionPxssh

class StreamLogger(object):
    def __init__(self, logger):
        self._log = logger
        self._buf = ''

    def write(self, msg):
        self._buf += msg.replace('\x0d','')
        if '\n' not in self._buf:
            return
        lines = self._buf.splitlines()
        if self._buf.endswith('\n'):
            self._buf = ''
        else:
            self._buf = lines[-1]
            lines = lines[:-1]
        for l in lines:
            self._log.info(l)
            if '[PEXPECT]' not in l:
                tag = incolor('%-15s:' % self._log.name, 'cyan', attrs='dark')
                print(tag, l)
        sys.stdout.flush()

    def flush(self):
        [h.flush() for h in self._log.handlers]

    def __del__(self):
        if self._buf:
            self.write('\n')
        self.flush()

class LoginError(Exception): pass

class Host(object):
    def __init__(self, hostname, username, password, logger, timeout=30):
        self._pass = password
        self._host = hostname
        self._user = username
        self._ssh = pxssh.pxssh(timeout=timeout)
        try:
            self._ssh.login(self._host, self._user, self._pass, login_timeout=timeout)
        except ExceptionPxssh as e:
            if e.value == 'password refused':
                raise LoginError('password')
            else:
                raise e
        except EOF:
            raise LoginError('eof')
        except TIMEOUT:
            raise LoginError('timeout')
        self._ssh.logfile = StreamLogger(logger)

    def close(self):
        self._ssh.close()

    def sh(self, cmd):
        self._ssh.sendline(cmd)
        self._ssh.prompt(timeout=None)
        return self._ssh.before
    
    def upload(self, src, dst):
        if self._pass is None:
            cmd = 'scp -pqr -o PasswordAuthentication=no %s %s@%s:%s' \
                % (src, self._user, self._host, dst)
            scp = pexpect.spawn(cmd)
            scp.expect(EOF)
            scp.close()
            return scp.exitstatus 
        else:
            cmd = 'scp -pqr -o PubkeyAuthentication=no %s %s@%s:%s' \
                % (src, self._user, self._host, dst)
            scp = pexpect.spawn(cmd)
            scp.expect('password:')
            scp.sendline(self._pass)
            scp.expect(EOF)
            scp.close()
            return scp.exitstatus 

def _make_logger(name, logdir):
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    fh = logging.FileHandler(logdir+ '/' + name, mode='w')
    log.addHandler(fh)
    return log
    
def worker(hostname, args):
    if args.verbose:
        print(incolor('starting: %s' % hostname, 'green', attrs='dark'))
    log = _make_logger(hostname, args.logdir)
    try:
        host = Host(hostname, args.username, args.password, log, args.timeout)
    except LoginError as e:
        print('\t', hostname, '\t', 'ERROR:', *e.args)
        print(incolor('stopping: %s' % hostname, 'red', attrs='dark'))
        return
    if args.src:
        host.sh('mkdir -p ' + args.dst)
        host.upload(args.src, args.dst)
    if args.dst != '~':
        host.sh("cd %s" % args.dst)
    host.sh(args.cmd)
    host.close()
    if args.verbose:
        print(incolor('stopping: %s' % hostname, 'red', attrs='dark'))

def make_arg_parser():
    parser = argparse.ArgumentParser(
                description="Mass Remote eXecute: automate scp and/or ssh "
                        "for multiple hosts.",
                epilog="Features: (1) non-interactive password entry; "
                        "(2) parallel execution; (3) logging; (4) file upload.",
                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('-H', '--hosts', nargs='+', metavar='HOST',
                help='remote host(s)')
    g.add_argument('-F', '--host-files', nargs='+', metavar='PATH',
                help='file(s) with one remote host per line')
    parser.add_argument('cmd', metavar='COMMAND', default=':', nargs='?',
                help='command to execute with DST as working directory; '
                    'in bash, colon (:) is noop')
    parser.add_argument('--logdir', default='/tmp/mrx_logs',
                help='log directory (%(default)s)')
    parser.add_argument('--threads', default=256, type=int,
                help='number of threads')
    parser.add_argument('--username', default='root',
                help='username')
    parser.add_argument('--password', metavar='SECRET',
                help='password; assume pubic key if omitted; prompt if -')
    parser.add_argument('--dst', default='~',
                help='upload destination path')
    parser.add_argument('--src',
                help="upload source path")
    parser.add_argument('--randomize', default=False, action='store_true',
                help="randomize order of hosts")
    parser.add_argument('--timeout', default=10, type=float, metavar='SECONDS',
                help="pxssh timeout")
    parser.add_argument('-v', '--verbose', default=False, action='store_true',
                help="verbose output")
    return parser

def main():
    parser = make_arg_parser()
    cfg = parser.parse_args()
    if cfg.verbose:
        print(cfg)
    if cfg.password == '-':
        cfg.password = getpass()
    if not os.path.exists(cfg.logdir):
        os.mkdir(cfg.logdir)
    if cfg.host_files:
        cfg.hosts = [l.strip() for f in cfg.host_files for l in open(f)]
    if cfg.randomize:
        random.shuffle(cfg.hosts)
    
    threads = []
    for h in cfg.hosts:
        t = Thread(target=worker, name=h, args=(h, cfg))
        t.daemon = True
        threads.append(t)

    print('Starting %s threads...' % len(threads))
    while threads:
        if active_count() - 1 > cfg.threads:
            sleep(0.1)
            continue
        threads.pop(0).start()
        # starting connections too quickly can cause problems
        # with ssh proxies (ProxyCommand)
        sleep(0.05)
        if cfg.verbose:
            print('Thread queue length: ', len(threads))
    print('Done starting threads')
    
    print('Press any key for status update')
    with NonBlockingConsole() as nbc:
        while active_count() > 1:
            if nbc.get_data():
                # print time so that something on the screen is guaranteed to 
                # change on key press (otherwise, when identical messages fill
                # the screen, it may seem that the application is not responding
                print(incolor(ctime(), 'white', attrs='bright'),
                        'Active threads:', sorted(t.name for t in threading.enumerate()))
                sys.stdout.flush()
            sleep(0.005)
    print('Main thread exit')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as e:
        print(e)
        sys.exit(1)
