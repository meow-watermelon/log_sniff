#!/usr/bin/env python3

import logging
import os
import re
import subprocess
import time
import yaml

def init_file_locations():
    global config_dir, log_dir, exec_shell_dir, lock_file
    config_dir = '/etc/log-sniff'
    log_dir = '/var/log/log-sniff'
    exec_log_dir = log_dir + '/scripts'
    exec_shell_dir = '/var/lib/log-sniff/shell'
    lock_file = '/var/run/log-sniff.lock'

def read_yaml(yaml_file):
    yaml_dict = {}

    try:
        f = open(yaml_file, 'rt')
    except OSError as e:
        error = e.strerror
        msg = 'Failed to open the sniff config %s: %s.' %(yaml_file,error)
        print(msg)
    else:
        try:
            yaml_data = yaml.load(f.read())
        except yaml.scanner.ScannerError:
            msg = 'Failed to parse the YAML content from %s.' %(yaml_file)
            print(msg)
        else:
            if yaml_data:
                yaml_dict = yaml_data
        finally:
            f.close()

    return yaml_dict

def gen_cmds(yaml_dict, script_dir):
    cmd_dict = {}

    script_name_prefix = yaml_dict['name']
    log_file = yaml_dict['log']

    cmd_dict['name'] = script_name_prefix
    cmd_dict[script_name_prefix] = {}
    cmd_dict[script_name_prefix]['log'] = log_file
    cmd_dict[script_name_prefix]['regexp_def'] = {}

    script_shebang = '#!/bin/sh'
    script_banner = '# log-sniff created script @ epoch: %d' %(int(time.time()))

    for sniff in yaml_dict['sniff']:
        if sniff['enabled']:
            script_sniff_prefix = sniff['sniff_name']
            script_commands = sniff['commands']

            script_filename = script_name_prefix + '.' + script_sniff_prefix + '.sh'
            script_abs_path = script_dir + '/' + script_filename

            try:
                with open(script_abs_path, 'wt') as f:
                    f.write(script_shebang + '\n')
                    f.write(script_banner + '\n')
                    f.write(script_commands)

                    cmd_dict[script_name_prefix]['regexp_def'][script_sniff_prefix] = {}
                    cmd_dict[script_name_prefix]['regexp_def'][script_sniff_prefix]['timeout'] = sniff['timeout']
                    cmd_dict[script_name_prefix]['regexp_def'][script_sniff_prefix]['regexp'] = sniff['regexp']
                    cmd_dict[script_name_prefix]['regexp_def'][script_sniff_prefix]['script'] = script_abs_path

                    msg = 'Script %s is created.' %(script_abs_path)
                    print(msg)
            except OSError as e:
                error = e.strerror
                msg = 'Failed to create the script %s: %s.' %(script_abs_path,error)
                print(msg)
        else:
            msg = 'Sniff %s is not enabled. Skipped.' %(sniff['sniff_name'])
            print(msg)

    return cmd_dict

def run_cmd(script, output_dir, timeout):
    cmd = ['/bin/sh', script, '&']
    script_basename = os.path.basename(script)
    timestamp = str(int(time.time()))
    stdout_file = output_dir + '/' + script_basename + '.' + timestamp + '.stdout'
    stderr_file = output_dir + '/' + script_basename + '.' + timestamp + '.stderr'

    if os.access(output_dir, os.W_OK):
        try:
            run = subprocess.run(args=cmd, capture_output=True, timeout=timeout, encoding='utf-8')
        except OSError as e:
            os_error_msg = e.strerror
            print('OS Error triggered while script %s running: %s') %(script_basename, os_error_msg)
        except subprocess.TimeoutExpired as e:
            timeout_err_msg = 'Timeout triggered while script %s running: %s sec(s).' %(script_basename, str(e.timeout))
            print(timeout_err_msg)

            if e.stdout != None:
                try:
                    with open(stdout_file, 'at') as f:
                        f.write(e.stdout.decode('utf-8'))
                        msg = 'Script STDOUT log %s saved.' %(stdout_file)
                        print(msg)
                except:
                    msg = 'Failed to write STDOUT of %s script.' %(script_basename)
                    print(msg)
            else:
                msg = 'No STDOUT captured on script %s execution.'  %(script_basename) 
                print(msg)

            if e.stderr != None:
                try:
                    with open(stderr_file, 'at') as f:
                        f.write(e.stderr.decode('utf-8'))
                        msg = 'Script STDERR log %s saved.' %(stderr_file)
                        print(msg)
                except:
                    msg = 'Failed to write STDERR of %s script.' %(script_basename)
                    print(msg)
            else:
                msg = 'No STDERR captured on script %s execution.'  %(script_basename) 
                print(msg)
        else:
            try:
                with open(stdout_file, 'at') as f:
                    f.write(run.stdout)
                    msg = 'Script STDOUT log %s saved.' %(stdout_file)
                    print(msg)
            except:
                msg = 'Failed to write STDOUT of %s script.' %(script_basename)
                print(msg)

            try:
                with open(stderr_file, 'at') as f:
                    f.write(run.stderr)
                    msg = 'Script STDERR log %s saved.' %(stderr_file)
                    print(msg)
            except:
                msg = 'Failed to write STDOUT of %s script.' %(script_basename)
                print(msg)
    else:
        msg = 'Script log dir %s is not writable.' %(output_dir)
        print(msg)

    return None

if __name__ == '__main__':
    print(read_yaml('defs/example.yaml'))
    yaml_dict = read_yaml('defs/example.yaml')
    cmds_def_dict = gen_cmds(yaml_dict, '/tmp')
    print(cmds_def_dict)
    sniff_name = cmds_def_dict['name']

    while True:
        try:
            with open(cmds_def_dict[sniff_name]['log'], 'rt') as log_fh:
                print('FILE OPEN GO')
                log_fh.seek(0, os.SEEK_END)
                while True:
                    log_line = log_fh.readline()
                    if log_line:
                        print(log_line)
                        print(cmds_def_dict[sniff_name]['regexp_def'].keys())
                        for regexp_tag in list(cmds_def_dict[sniff_name]['regexp_def'].keys()):
                            print(regexp_tag)
                            regexp = cmds_def_dict[sniff_name]['regexp_def'][regexp_tag]['regexp']
                            print(regexp)
                            if re.search(regexp, log_line):
                                print('MATCH GO')
                                # a match is toggled, triggering the script...
                                sniff_script = cmds_def_dict[sniff_name]['regexp_def'][regexp_tag]['script']
                                sniff_script_timeout = cmds_def_dict[sniff_name]['regexp_def'][regexp_tag]['timeout']
                                print(sniff_script, sniff_script_timeout)
                                run_cmd(sniff_script, '/home/ericlee/Projects/repo/log_sniff/run', sniff_script_timeout)

                    if not os.path.exists(cmds_def_dict[sniff_name]['log']):
                        print('File does not exist, sleep 1 second and re-open the file again...')
                        time.sleep(1)
                        break

                    time.sleep(0.005)
                    log_fh.seek(0, 1)
        except:
            print('Failed to open the file, sleep 1 second and re-open the file again...')
            time.sleep(1)
            continue
        else:
            pass
