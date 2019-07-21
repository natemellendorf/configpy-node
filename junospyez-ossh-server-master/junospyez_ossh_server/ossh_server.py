from threading import Thread
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConnectError
from jnpr.junos.utils.sw import SW
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
from junospyez_ossh_server.log import logger
import redis
import requests
from pprint import pprint
import os, sys
import tempfile
from datetime import datetime
import time
import socket
import json
import warnings
from lxml import etree
import xmltodict
import socketio


warnings.filterwarnings(action='ignore', module='.*paramiko.*')
__all__ = ['OutboundSSHServer']

def get_time():
    current_time = str(datetime.now().time())
    no_sec = current_time.split('.')
    poll = no_sec.pop(0)
    return poll


def new_log_event(**kwargs):
    device_sn = kwargs.get('device_sn', '__UNKNOWN__')
    event = kwargs.get('event', '')
    configpy_url = kwargs.get('configpy_url', 'http://10.0.0.204:80')
    sio = kwargs.get('sio', None)

    log = f'[{get_time()}][{device_sn}]: {event}'
    logger.info(log)

    try:
        if sio:
            data = {'event_time': get_time(), 'event': f'[{device_sn}]: {event}'}
            sio.emit('hub_console', data)

    except Exception as e:
        logger.info(f'SocketIO Exception: {str(e)}')


def convert(data):
    json_data = json.dumps(data)
    result = json.loads(json_data)
    return result


def repo_sync(redis, facts, **kwargs):
    sio = kwargs['sio']
    words = kwargs["repo_uri"].split("/")
    protocol = words[0]
    domain = words[2]
    gitlab_url = '{0}//{1}'.format(protocol, domain)
    findall = '{0}/api/v4/projects/'.format(gitlab_url)

    headers = {
        'PRIVATE-TOKEN': "{0}".format(kwargs['repo_auth_token']),
        'Content-Type': "application/json",
        'User-Agent': "ConfigPy-Node",
        'Accept': "*/*",
        'Cache-Control': "no-cache",
        'Connection': "keep-alive",
        'cache-control': "no-cache"
    }

    querystring = {"per_page": "100"}

    try:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Reaching out to gather repo information...')
        r = requests.get(findall, headers=headers, params=querystring, timeout=5)

        if r.status_code == 200:
            returned = r.json()
        else:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to access repo.')
            raise Exception(f'{r.text}')

    except Exception as e:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{str(e)}')
        redis.hmset(kwargs["device_sn"], {'config': 'repo error'})
        redis.hmset(kwargs["device_sn"], {'repo_error': f'{str(e)}'})
        return

    for x in returned:
        if x['path_with_namespace'] in kwargs["repo_uri"]:
            raw_config_file = f'{findall}/{x["id"]}/repository/files/{kwargs["cid"]}%2F{kwargs["device_sn"]}%2Eset/raw?ref=master'

            try:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Grabbing config file from repo...')
                returned = requests.get(raw_config_file, headers=headers, timeout=5)

                if returned.status_code == 200:
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Device config acquired.')
                    url_list = ['edit', 'blob']
                    for item in url_list:
                        url = f'{kwargs["repo_uri"]}/{item}/master/{kwargs["cid"]}/{kwargs["device_sn"]}.set'
                        redis.hmset(kwargs["device_sn"], {f'device_repo_{item}': f'{url}'})
                        print(url)

                    return returned
                else:
                    raise Exception(f'{returned.text}')
            except Exception as e:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{str(e)}')
                redis.hmset(kwargs["device_sn"], {'config': 'repo error'})
                redis.hmset(kwargs["device_sn"], {'repo_error': f'{str(e)}'})
                return


def cluster_srx(**kwargs):
    if kwargs['dev'] and kwargs['sio'] and kwargs['facts'] and kwargs['ztp_cluster_node']:
        dev = kwargs['dev']
        sio = kwargs['sio']
        facts = kwargs['facts']
        ztp_cluster_node = kwargs['ztp_cluster_node']

        try:
            dev.rpc.set_chassis_cluster_enable(cluster_id='100', node=ztp_cluster_node, reboot=True)
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Device assigned node id: {ztp_cluster_node}')

        except Exception as e:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Error: {str(e)}')


def update_config(device, facts, r, repo_uri, repo_auth_token, sio=None):

    # Attempt to find the config file for the connected device
    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Searching {repo_uri} in directory {facts["cid"]} for {facts["device_sn"]}.set')

    conf_file = repo_sync(r, facts, repo_uri=repo_uri, cid=facts['cid'], device_sn=facts['device_sn'], repo_auth_token=repo_auth_token, sio=sio)

    # If found, save the file so it can be loaded by PyEz.
    config_file_location = f'configs/{facts["device_sn"]}.set'

    try:
        if conf_file:
            print('Writing to file')
            with open(config_file_location, "w") as file:
                file.write(conf_file.text)
    except AttributeError:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to access remote repo')
        r.hmset(facts['device_sn'], {'config': 'repo error'})
        return
    except Exception as e:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to access remote repo')
        r.hmset(facts['device_sn'], {'config': 'repo error'})
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'default exception.')
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{str(e)}')
        return

    # Check to see if config file exists.
    # It should, but we'll check anyway.
    if os.path.exists(config_file_location):

        device.bind(cu=Config)
        device.timeout = 300

        # Lock the configuration, load configuration changes, and commit
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Locking the configuration')
        try:
            device.cu.lock()
        except LockError as err:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to lock configuration: {err}')
            device.close()
            return

        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Loading configuration changes')

        try:
            device.cu.load(path=config_file_location, merge=True, ignore_warning='statement not found')
        except (ConfigLoadError, Exception) as err:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to load configuration changes: {err}')
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unlocking the configuration')
            try:
                device.cu.unlock()
            except UnlockError:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to unlock configuration: {err}')
            try:
                os.remove(config_file_location)
            except Exception as e:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to delete {config_file_location}')
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{str(e)}')

            device.close()
            return

        show_compare = device.cu.diff(rb_id=0)

        if show_compare is None:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'*** No changes needed...')
            try:
                r.hmset(facts['device_sn'], {'config': 'compliant'})
            except Exception as e:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{e}')

        else:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Changes found!')
            try:
                r.hmset(facts['device_sn'], {'config': 'non-compliant'})
                r.hmset(facts['device_sn'], {'last change': show_compare})
            except Exception as e:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{e}')
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{show_compare}')
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Updating config...')

            try:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Running commit check...')
                try:
                    r.hmset(facts['device_sn'], {'config': 'running commit check'})
                except Exception as e:
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{e}')

                if device.cu.commit_check() is True:
                    try:
                        r.hmset(facts['device_sn'], {'config': 'commit check passed'})
                        r.hmset(facts['device_sn'], {'config': 'running commit confirmed'})
                    except Exception as e:
                        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{e}')
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Commit check passed.')
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'running commit confirmed')


                    try:
                        commit = device.cu.commit(comment='Loaded by DSC.', confirm=2, timeout=240)

                        if commit:
                            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Commit complete.')
                            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Confirming changes...')
                            try:
                                r.hmset(facts['device_sn'], {'config': 'confirm commit'})
                            except Exception as e:
                                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{str(e)}')

                            if device.cu.commit_check():
                                try:
                                    r.hmset(facts['device_sn'], {'config': 'compliant'})
                                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Commit confirmed.')
                                except Exception as e:
                                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{e}')

                    except Exception as e:
                        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{e}')
                        r.hmset(facts['device_sn'], {'config': 'device lost'})
                        return
                else:
                    r.hmset(facts['device_sn'], {'config': 'commit check failed'})
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Commit check failed...')
                    device.cu.unlock()
                    try:
                        os.remove(config_file_location)
                    except Exception as e:
                        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to delete {config_file_location}')
                        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{e}')

            except CommitError as err:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to commit configuration: {err}')
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unlocking the configuration')
                try:
                    device.cu.unlock()
                except UnlockError as err:
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to unlock configuration: {err}')

                try:
                    os.remove(config_file_location)
                except Exception as e:
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to delete {config_file_location}')
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{str(e)}')

                device.close()
                return

        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unlocking the configuration')
        try:
            device.cu.unlock()
        except UnlockError as err:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to unlock configuration: {err}')
            device.close()
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Removing local config file')

        try:
            os.remove(config_file_location)
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Config removed.')
        except Exception as e:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Unable to delete {config_file_location}')
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{str(e)}')

    else:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Config was not found for {facts["device_sn"]}')
        r.hmset(facts['device_sn'], {'configpy-node_error': 'Could not locate config in configs/'})
        r.hmset(facts['device_sn'], {'config': 'repo error'})

    return
    

def gather_basic_facts(device, r, sio):
    """
    Using the provide Junos Device object, retrieve basic facts about the device.

    Parameters
    ----------
    device : Device
        The Junos device instance

    Returns
    -------
    dict
        A collection of basic facts about the device that will be stored in the database.
    """
    # -----------------------------------------------------
    # get information from the provided device facts object
    # -----------------------------------------------------

    basic_facts = dict()
    for x, y in device.facts.items():
        basic_facts[f'{x}'] = f'{y}'

    # TODO: Most if this code below should be reworked.
    basic_facts['device_sn'] = device.facts['serialnumber']
    
    if device.facts['hostname'] is None:
        basic_facts['hostname'] = 'no_hostname'
        new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'No hostname')
    else:
        basic_facts['hostname'] = device.facts['hostname']

    if device.facts['srx_cluster']:
        new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'Device: SRX Cluster!')
        basic_facts['srx_cluster'] = 'True'
        basic_facts['os_version'] = device.facts['version_RE0']

        try:
            basic_facts['device_model'] = device.facts['model_info']['node0']
        except:
            basic_facts['device_model'] = 'error'
        try:
            basic_facts['hostname'] = device.facts['hostname_info']['node0']
        except:
            basic_facts['device_model'] = 'error'
    else:
        # Gather general faqs
        basic_facts['os_version'] = device.facts['version']
        basic_facts['device_model'] = device.facts['model']
    
    
    # FIXME - Likely a better way to handle this error if contact is not found.
    # Get SNMP contact ID:
    try:
        # Look for SNMP contact in config.
        new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'Attempting to find SNMP in config..')
        snmp_config = device.rpc.get_config(filter_xml='snmp/contact')
        found_snmp_value = etree.tostring(snmp_config, encoding='unicode')
        parsed_snmp_value = xmltodict.parse(found_snmp_value)
        #pprint(parsed_snmp_value['configuration']['snmp']['contact'])
        #config = device.rpc.get_config(filter_xml='snmp', options={'format':'json'})
        new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'{parsed_snmp_value["configuration"]["snmp"]["contact"]}')
        basic_facts['cid'] = parsed_snmp_value['configuration']['snmp']['contact']
        new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'CID saved to redis db')

    except Exception as e:
        new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'No CID found in the device config')
        new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'{str(e)}')
        # Index error is for if the SNMP contact is not defined in the config.
        try:
            '''
            # Lets see if ConfigPy set a bootstrap SNMP client ID in the Redis DB.
            # This would happen when someone generates a config with ConfigPy.
            # and then they push it to the GitLab repo.
            # when pushed, the config is assigned to a client contact ID (folder) in GitLab.
            # If a bootstrap ID is detected in the Redis DB, then we'll copy it to the Redis CID value.
            # So in a way, I think of this as a sort of bootstrap.
            # Without this, we have no way to find the config file for a new (out of box) device.
            '''

            # Get redis keys for this device
            redis_info = r.hgetall(device.facts['serialnumber'])
            # Get the ztp, if one exists. Else, hit the KeyError exception.
            ztp = redis_info[b'ztp'].decode("utf-8")
            # If it's found, let's make that the new cid value.
            if ztp:
                basic_facts['cid'] = str(ztp)
                new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'found ZTP flag!')
                new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'setting CID value to {str(ztp)}')
            else:
                # Shouldn't be used, but just in case.
                new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'No ZTP flag set in redis')
                basic_facts['cid'] = 'none'
        except KeyError:
            # ztp isn't a valid key, so no ztp.
            new_log_event(sio=sio, device_sn=basic_facts["device_sn"], event=f'Exception..setting CID to none.')
            basic_facts['cid'] = 'none'

    # -------------------------------------------------------------------------------
    # need to do a route lookup using the outbound ssh config to determine the actual
    # management interface used to reach this service.  For now, use the first
    # server ip-address (name).  It is possible that the device could be configured
    # with multiple ossh clients.  If we need to support this use-case, then we will
    # need to add additional checks for specific client name.
    # -------------------------------------------------------------------------------

    config = device.rpc.get_config(filter_xml='system/services/outbound-ssh')
    servers = config.xpath('.//servers/name')
    server_ipaddr = servers[0].text

    # -----------------------------------------------------------------------------------
    # get mgmt_interface value from the route lookup.  The route lookup will give use the
    # logical interface name, which we will also need for finding the assigned ip-address
    # -----------------------------------------------------------------------------------

    resp = device.rpc.get_route_information(destination=server_ipaddr)
    if_name = resp.xpath('.//via | .//nh-local-interface')[0].text
    basic_facts['mgmt_interface'] = if_name.partition('.')[0]   # physical interface

    # -------------------------------------------------------------
    # get mgmt_ipaddr from the if_name obtained by the route lookup
    # -------------------------------------------------------------

    if_info = device.rpc.get_interface_information(interface_name=if_name, terse=True)
    basic_facts['mgmt_ipaddr'] = if_info.findtext('.//ifa-local').partition('/')[0].strip()

    # ----------------------------------------------------------
    # get mgmt_macaddr value assigned to the management interface
    # ----------------------------------------------------------

    resp = device.rpc.get_interface_information(interface_name=basic_facts['mgmt_interface'], media=True)
    found = resp.findtext('.//current-physical-address').strip()
    basic_facts['mgmt_macaddr'] = found

    return basic_facts


def check_backup_firmware(device, facts, sio):

    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Setting connection timeout to 300 seconds.')
    device.timeout = 300

    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Gathering snapshot details.')
    result = device.rpc.get_snapshot_information(slice='alternate', media='internal')
    result = etree.tostring(result, encoding='unicode')
    parsed_snmp_value = xmltodict.parse(result)

    sw_version = []

    for x in parsed_snmp_value['snapshot-information']['software-version']:
        if x['package']['package-name'] == 'junos':
            sw_version.append(x['package']['package-version'])

    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Found: {sw_version}')

    if len(sw_version) == 2 and sw_version[0] != sw_version[1]:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Mismatch detected!')
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Updating backup firmware...')
        result = device.rpc.request_snapshot(slice='alternate')
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Result: {result}')

def xml_to_dict(var):
    result = etree.tostring(var, encoding='unicode')
    final_dict = xmltodict.parse(result)
    return final_dict

def find_checksum(dev, destination=None):
    result = dev.rpc.get_checksum_information(path=f'{destination}')
    parsed_checksum_value = xml_to_dict(result)
    found_checksum = parsed_checksum_value['checksum-information']['file-checksum'].get('checksum', None)
    return found_checksum

def upload_file(dev, sio, facts, source=None, destination=None, srx_firmware_checksum=None, **kwargs):
    found_checksum = None
    if source and destination:
        # Check to see if file exists on the device.
        try:
            result = dev.rpc.file_list(path=f'{destination}')
            result = xml_to_dict(result)
            if result['directory-list']['directory']['file-information']['file-name'] == destination:
                new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'File exists. Checking file checksum...')
                found_checksum = find_checksum(dev, destination)
                if found_checksum and found_checksum == srx_firmware_checksum:
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Checksum matched!')
                    return 0
                else:
                    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Existing file checksum does not match.')
        except Exception as e:
            pass

        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Uploading file... Please be patient...')
        dev.rpc.file_copy(source=f'{source}', destination=f'{destination}')
        found_checksum = find_checksum(dev, destination)
        if found_checksum and found_checksum == srx_firmware_checksum:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Upload complete. Checksum matched!')
            return 0
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'ERROR: Upload complete, but checksum does not match!')
        return 1
    else:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'ERROR: Upload failed. Invalid source or destination.')
        return 1


def update_cluster(dev, software_location, srx_firmware, r, facts, sio, srx_firmware_checksum):
    # Set default values for function.
    dev.timeout = 600
    result = 1

    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Searching for firmware and uploading if needed.')
    result = upload_file(dev, sio, facts, source=f'{software_location}{srx_firmware}', destination=f'/var/tmp/{srx_firmware}', srx_firmware_checksum=srx_firmware_checksum)

    # If checksum was found and it matched the provided checksum, then perform ISSU.
    if result == 0:
        # FIXME: I would like to use the below, but it doesn't return any useful results...
        # result = dev.rpc.request_package_in_service_upgrade(package_name=f'/var/tmp/{srx_firmware}', no_sync=True)
        result = dev.cli(f'request system software in-service-upgrade {srx_firmware} no-sync')

        if 'ISSU not allowed' in result:
            new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'ERROR: {result}')
            return 1

        else:
            return 0

    # If any of the above is invalid, send an error syslog.
    elif result == 1:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'ERROR: Unable to upload file to device.')
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'ERROR: Aborting upgrade.')
        return 1


def update_firmware(device, software_location, srx_firmware_url, r, facts, sio):
    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Starting software update...')
    r.hmset(facts['device_sn'], {'firmware_update': 'Starting software update...'})

    def update_progress(device, report):
        # log the progress of the installing process
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{report}')
        r.hmset(facts['device_sn'], {'firmware_update': f'{report}'})

    package = f'{software_location}{srx_firmware_url}'
    remote_path = '/var/tmp'
    validate = True

    # Create an instance of SW
    new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Creating an instance of SW')
    device.bind(sw=SW)

    try:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Running installer...')
        r.expire(facts['device_sn'], 2400)
        r.hmset(facts['device_sn'], {'firmware_update': 'Running installer...'})
        status = device.sw.install(package=package, remote_path=remote_path, progress=update_progress, validate=validate, timeout=2400, checksum_timeout=400)

    except Exception as err:
        msg = f'Unable to install software, {err}'
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{msg}')
        status = False

        return

    if status is True:
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Software installation complete.')
        rsp = device.sw.reboot(all_re=False)
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'Upgrade pending reboot cycle, please be patient.')
        new_log_event(sio=sio, device_sn=facts["device_sn"], event=f'{rsp}')

    return



class OutboundSSHServer(object):

    NAME = 'outbound-ssh-server'
    DEFAULT_LISTEN_BACKLOG = 10
    logger = logger

    def __init__(self, ipaddr, port, login_user, login_password, configpy_url, redis_url, repo_uri, repo_auth_token, software_location, srx_firmware, srx_firmware_checksum, on_device=None, on_error=None, unittest=None):
        """
        Parameters
        ----------
        ipaddr : str
            The server IP address

        port : int
            The server port to accept requests

        login_user : str
            The device login user name

        login_password : str
            The device login password

        on_device : callaback
            User callback function that is invoked when the server has remote device NETCONF establish
            and has retrieved basic facts.  The callback takes two parameters, the PyEZ device instance,
            and a dictionary of gathered basic facts, for example:

            >>> import json
            >>>
            >>> def dump_facts(device, facts):
            >>>     print("GOT FACTS: ", json.dumps(facts, indent=3))

        on_error : callback
            User callback function that is invoked when error occurs when attempting to
            connect or communicate with remote device.  The callback takes two parameters, the PyEZ device
            instance (could be None) and the error exception instance, for example:

            >>> import json
            >>>
            >>> def dump_error(device, exc):
            >>>     print("GOT ERROR: ", str(exc))
        """



        self.thread = None
        self.socket = None
        self.login_user = login_user
        self.login_password = login_password
        self.configpy_url = configpy_url
        self.redis_url = redis_url
        self.repo_uri = repo_uri
        self.software_location = software_location
        self.srx_firmware = srx_firmware
        self.srx_firmware_checksum = srx_firmware_checksum
        self.repo_auth_token = repo_auth_token
        self.bind_ipaddr = ipaddr
        self.bind_port = int(port)
        self.listen_backlog = OutboundSSHServer.DEFAULT_LISTEN_BACKLOG

        self._callbacks = dict()

        self.on_device = on_device      # callable also provided at :meth:`start`
        self.on_error = on_error        # callable also provided at :meth:`start`

        self.r = redis.Redis(host=redis_url, port=6379, db=0)

        self.sio = socketio.Client()
        self.sio.connect(configpy_url)


    # ----------------------------------------------------------------------------------------------------------------
    # PROPERTIES
    # ----------------------------------------------------------------------------------------------------------------

    @property
    def name(self):
        return self.__class__.NAME

    @property
    def on_device(self):
        def no_op(device, facts):
            pass

        return self._callbacks['on_device'] or no_op

    @on_device.setter
    def on_device(self, callback):
        if callback and not callable(callback):
            raise ValueError('callback is not callable')

        self._callbacks['on_device'] = callback

    @property
    def on_error(self):
        def no_op(device, exc):
            pass

        return self._callbacks['on_error'] or no_op

    @on_error.setter
    def on_error(self, callback):
        if callback and not callable(callback):
            raise ValueError('callback is not callable')

        self._callbacks['on_error'] = callback

    # ----------------------------------------------------------------------------------------------------------------
    # PRIVATE METHODS
    # ----------------------------------------------------------------------------------------------------------------

    def _setup_server_socket(self):
        s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_sock.bind((self.bind_ipaddr, self.bind_port))
        s_sock.listen(self.listen_backlog)
        self.socket = s_sock

    def _server_thread(self):
        """
        This is the running thread target for the outbound-ssh server.  The purpose of this thread
        is to await inbound connections from the Junos devices and then spawn a specific thread for that device
        for future processing.
        """

        try:
            self._setup_server_socket()

        except Exception as exc:
            new_log_event(event=f'{self.name}: failed to setup socket: {str(exc)}')
            return

        while True:

            # await a device to make an outbound connection.  The socket accept() returns a tuple
            # (socket, (device ipaddr, device port)).  create a new thread to process the inbound with
            # this information

            try:
                in_sock, (in_addr, in_port) = self.socket.accept()

            except ConnectionAbortedError:
                # this triggers when the server socket is closed by the shutdown() method
                new_log_event(event=f'{self.name} shutting down')
                return

            in_str = f'{in_addr}:{in_port}'
            dev_name = f'device-{in_str}'
            new_log_event(event=f'{self.name}: accepted connection from {in_str}')

            # spawn a device-specific thread for further processing

            try:
                Thread(name=dev_name, target=self._device_thread,
                       kwargs=dict(in_sock=in_sock, in_addr=in_addr, in_port=in_port)).start()

            except RuntimeError as exc:
                new_log_event(event=f'{self.name}: ERROR: failed to start processing {in_addr}: {str(exc)}')
                in_sock.close()
                continue

        # NOT REACHABLE

    def _device_thread(self, in_sock, in_addr, in_port):
        """
        This is a thread target function that is launched by the OSSH service.  The purpose of this function
        is to make a NETCONF connection back to the device, gather basic facts, and store them into the database.

        If all goes well, the `facts` field in the database will contain the information about the device.  If
        all does not go well, then there is an "error" field within the facts that the caller can example.  The
        most likely error reason is the provided user name and password values are not correct.

        Parameters
        ----------------
        in_addr: str
            the Junos device management IP address that connected to the OSSH service

        in_sock: socket
            the socket instance from the outbound connection.
        """

        via_str = f'{in_addr}:{in_port}'

        sock_fd = in_sock.fileno()

        # attempt to add this device entry to the database; the unique ID is the IP address.
        # it is AOK if the entry already exists as the device-thread will simply update the record with the
        # information retrieved

        try:
            new_log_event(sio=self.sio, event=f'establishing netconf to device via: {via_str}')
            dev = Device(sock_fd=sock_fd, user=self.login_user, password=self.login_password)
            dev.open()

        except ConnectError as exc:
            new_log_event(sio=self.sio, event=f'Connection error to device via {via_str}: {exc.msg}')
            in_sock.close()
            return

        except Exception as exc:
            new_log_event(sio=self.sio, event=f'unable to establish netconf to device via {via_str}: {str(exc)}')
            in_sock.close()

        # #######################################
        # Begin Working With Device
        # #######################################

        try:

            # #######################################
            # Gather Device Facts
            # #######################################

            new_log_event(sio=self.sio, event=f'Gathering basic facts from device via: {via_str}')
            facts = gather_basic_facts(dev, self.r, self.sio)
            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Finished gathering facts.')

            try:
                facts = convert(facts)
                self.r.hmset(facts['device_sn'], facts)
                self.r.hmset(facts['device_sn'], {'Last seen': get_time()})
                self.r.expire(facts['device_sn'], 300)
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'database for {facts["device_sn"]} will expire in 5 min.')
            except Exception as e:
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'{str(e)}')

            # #######################################
            # Firmware Check / Update
            # #######################################

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event='***** TASK : Starting firmware audit...', configpy_url=self.configpy_url)

            # Check is SRX 300, 320, 340, or 345:
            if 'SRX3' in facts['device_model']:
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Device type: SRX')
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Device firmware: {facts["os_version"]}')

                # Check for a firmware mismatch:
                if facts['os_version'] not in self.srx_firmware and '.tgz' in self.srx_firmware:
                    new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Desired firmware: {self.srx_firmware}')
                    new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Firmware mismatch detected')

                    # Start firmware upgrade if device is not in an SRX cluster.
                    if facts['srx_cluster'] == 'False':
                        new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Device is not in a cluster.')
                        self.r.hmset(facts['device_sn'], {'config': 'updating firmware'})
                        self.r.expire(facts['device_sn'], 900)
                        new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Set device DB timeout for 15 min while update is performed.')

                        update_firmware(dev, self.software_location, self.srx_firmware, self.r, facts, self.sio)

                        dev.close()
                        new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Disconnecting - Device needs to reboot.')
                        return

                    elif facts['srx_cluster'] == 'True':
                        # Attempt to perform ISSU on the SRX cluster
                        new_log_event(sio=self.sio, device_sn=facts["device_sn"], event='Starting Cluster firmware audit...', configpy_url=self.configpy_url)

                        try:
                            status = update_cluster(dev, self.software_location, self.srx_firmware, self.r, facts, self.sio, self.srx_firmware_checksum)
                        except Exception as e:
                            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'ERROR: {str(e)}')
                            return

                        if status == 0:
                            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Disconnecting device.')
                            dev.close()
                        elif status == 1:
                            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'ERROR: ISSU firmware upgrade failed.')

                    else:
                        # This code should not be reached..
                        new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'ERROR: unreachable code reached!')
                        pass

                elif facts['os_version'] in self.srx_firmware and '.tgz' in self.srx_firmware:
                    new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Desired firmware: {self.srx_firmware}')
                    new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Firmware is compliant.')

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Firmware audit complete.')

            # #######################################
            # Backup Firmware Check / Update
            # #######################################

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Starting Backup Firmware audit...')

            try:
                check_backup_firmware(dev, facts, self.sio)
            except Exception as e:
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Error: {str(e)}')

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Backup Firmware audit complete.')

            # #######################################
            # Configure Clustering
            # #######################################

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Starting ZTP cluster audit')
            device_db = self.r.hgetall(facts["device_sn"])

            device_values = {}
            for x, y in device_db.items():
                device_values[x.decode("utf-8")] = y.decode("utf-8")

            if 'ztp_cluster_node' in device_values:
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'ZTP cluster flag set!')

                cluster_srx(dev=dev, sio=self.sio, facts=facts, ztp_cluster_node=device_values['ztp_cluster_node'])

                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : ZTP Cluster audit complete')

                try:
                    self.r.hdel(facts['device_sn'], 'ztp_cluster_node')
                    new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Successfully removed "ztp_cluster_node"')
                except Exception as e:
                    new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Failed to remove "ztp_cluster_node" key.')

                dev.close()
                self.r.hmset(facts['device_sn'], {'config': 'clustering'})
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Disconnecting - Device needs to reboot.')

                return

            else:
                new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'ZTP Cluster flag not set.')

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : ZTP Cluster audit complete')

            # #######################################
            # Config Check / Update
            # #######################################

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Starting config audit...')
            update_config(dev, facts, self.r, self.repo_uri, self.repo_auth_token, sio=self.sio)
            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'***** TASK : Config audit complete')

            # call user on-device callback
            # self.on_device(dev, facts)

            new_log_event(sio=self.sio, device_sn=facts["device_sn"], event=f'Completed device with management IP address: {facts["mgmt_ipaddr"]}')

            dev.close()
            new_log_event(sio=self.sio, event=f'{"- " * 30}')

        except Exception as exc:
            error = f"ERROR: unable to process device {in_addr}:{in_port}: %s" % str(exc)
            new_log_event(sio=self.sio, event=f'{error}')
            sys.exit(1)
            if self.on_error:
                self.on_error(dev, exc)

        finally:
            in_sock.close()
            sys.exit(1)
            return

    # ----------------------------------------------------------------------------------------------------------------
    # PUBLIC METHODS
    # ----------------------------------------------------------------------------------------------------------------

    def start(self, on_device=None, on_error=None):
        """
        Start the ossh-server background thread.

        Examples
        --------
        Start the server, will use the existing server attributes.

            >>> ok, msg = server.start()

        Start the server, provide a new `on_device` callback.

            >>> import json
            >>>
            >>> def dump_facts(device, facts):
            >>>     print("GOT FACTS: ", json.dumps(facts, indent=3))
            >>>
            >>> ok, msg = server.start(on_device=dump_facts)

        Parameters
        ----------
        on_device : callaback
            User callback function that is invoked when the server has remote device NETCONF establish
            and has retrieved basic facts.

        on_error : callback
            User callback function that is invoked when error occurs when attempting to
            connect or communicate with remote device.

        Returns
        -------
        tuple
            ok : bool
                True if started ok, False otherwise
            msg : str
                message string
        """

        if self.socket:
            msg = f'{self.name} already running'
            new_log_event(event=f'{msg}')
            return False, msg

        if on_device:
            self.on_device = on_device

        if on_error:
            self.on_error = on_error

        new_log_event(event=f'{self.name}: starting on {self.bind_ipaddr}:{self.bind_port}')

        try:
            self.thread = Thread(name=self.name, target=self._server_thread)
            self.thread.start()

        except Exception as exc:
            msg = f'{self.name} unable to start: %s' % str(exc)
            new_log_event(event=f'{msg}')
            return False, msg

        msg = f'{self.name}: started'
        new_log_event(event=f'{msg}')
        return True, msg

    def stop(self):
        '''
        Stops the ossh-server thread.

        Examples
        --------
            >>> server.stop()
        '''
        self.socket.close()
        self.thread = None
        self.socket = None
        new_log_event(event=f'{self.name}: stopped')
