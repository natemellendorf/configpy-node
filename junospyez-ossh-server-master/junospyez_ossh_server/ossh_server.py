from threading import Thread
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
from junospyez_ossh_server.log import logger
import redis
import requests
from pprint import pprint
import os
import tempfile
from datetime import datetime
import socket
import json
import warnings
from lxml import etree


warnings.filterwarnings(action='ignore', module='.*paramiko.*')
__all__ = ['OutboundSSHServer']


def convert(data):

    json_data = json.dumps(data)
    result = json.loads(json_data)
    return result


def repo_sync(redis, **kwargs):

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
        logger.info('Reaching out to gather repo information...')
        r = requests.get(findall, headers=headers, params=querystring, timeout=5)
        returned = r.json()

    except Exception as e:
        logger.error(str(e))
        redis.hmset(kwargs["device_sn"], {'config': 'repo error'})
        redis.hmset(kwargs["device_sn"], {'repo_error': f'{str(e)}'})
        return

    for x in returned:
        if x['path_with_namespace'] in kwargs["repo_uri"]:
            raw_config_file = f'{findall}/{x["id"]}/repository/files/{kwargs["cid"]}%2F{kwargs["device_sn"]}%2Eset/raw?ref=master'
            try:
                logger.info('Grabbing device config from repo...')
                returned = requests.get(raw_config_file, headers=headers, timeout=5)
                if returned.status_code == 200:
                    return returned
                else:
                    raise Exception(f'{returned.text}')
            except Exception as e:
                logger.error(str(e))
                redis.hmset(kwargs["device_sn"], {'config': 'repo error'})
                redis.hmset(kwargs["device_sn"], {'repo_error': f'{str(e)}'})
                return


def update_config(device, facts, r, repo_uri, repo_auth_token):

    # FIXME - This whole function should be reviewed and cleaned up.

    # Attempt to find the config file for the connected device
    logger.info(f'Searching {repo_uri} in directory {facts["cid"]} for {facts["device_sn"]}.set')

    conf_file = repo_sync(r, repo_uri=repo_uri, cid=facts['cid'], device_sn=facts['device_sn'],
                       repo_auth_token=repo_auth_token)

    '''
    WIP:
    try:
        new_file, filename = tempfile.mkstemp()

        print(filename)
    except Exception as e:
        logger.error(str(e))
    '''

    # FIXME - This is not ideal, and should be modified so the config is never written to the local storage.

    # If found, save the file so it can be loaded by PyEz.
    config_file_location = f'configs/{facts["device_sn"]}.set'

    try:
        if conf_file:
            print('Writing to file')
            with open(config_file_location, "w") as file:
                file.write(conf_file.text)
    except AttributeError:
        logger.error('Unable to access remote repo')
        r.hmset(facts['device_sn'], {'config': 'repo error'})
        return
    except Exception as e:
        logger.error('Unable to access remote repo')
        r.hmset(facts['device_sn'], {'config': 'repo error'})
        logger.error('default exception.')
        logger.error(str(e))
        return

    # Check to see if config file exists.
    # It should, but we'll check anyway.
    if os.path.exists(config_file_location):

        device.bind(cu=Config)
        device.timeout = 300

        # Lock the configuration, load configuration changes, and commit
        logger.info("Locking the configuration")
        try:
            device.cu.lock()
        except LockError as err:
            logger.info("Unable to lock configuration: {0}".format(err))
            device.close()
            return

        logger.info("Loading configuration changes")

        try:
            device.cu.load(path=config_file_location, merge=True, ignore_warning='statement not found')
        except (ConfigLoadError, Exception) as err:
            logger.info("Unable to load configuration changes: {0}".format(err))
            logger.info("Unlocking the configuration")
            try:
                device.cu.unlock()
            except UnlockError:
                logger.info("Unable to unlock configuration: {0}".format(err))
            try:
                os.remove(config_file_location)
            except Exception as e:
                logger.error(f'Unable to delete {config_file_location}')
                logger.error(str(e))

            device.close()
            return

        show_compare = device.cu.diff(rb_id=0)

        if show_compare is None:
            logger.info('*** No changes needed...')
            try:
                r.hmset(facts['device_sn'], {'config': 'compliant'})
            except Exception as e:
                logger.info(e)

        else:
            logger.info('Changes found:')
            try:
                r.hmset(facts['device_sn'], {'config': 'non-compliant'})
                r.hmset(facts['device_sn'], {'last change': show_compare})
            except Exception as e:
                logger.info(e)
            logger.info(show_compare)
            logger.info('Updating config...')

            try:
                logger.info('Running commit check...')
                try:
                    r.hmset(facts['device_sn'], {'config': 'running commit check'})
                except Exception as e:
                    logger.info(e)

                if device.cu.commit_check() is True:
                    try:
                        r.hmset(facts['device_sn'], {'config': 'commit check passed'})
                        r.hmset(facts['device_sn'], {'config': 'running commit confirmed'})
                    except Exception as e:
                        logger.info(e)
                    logger.info('Commit check passed.')
                    logger.info('running commit confirmed')


                    try:
                        commit = device.cu.commit(comment='Loaded by DSC.', confirm=2, timeout=240)

                        if commit:
                            logger.info('Commit complete.')
                            logger.info('Confirming changes...')
                            try:
                                r.hmset(facts['device_sn'], {'config': 'confirm commit'})
                            except Exception as e:
                                logger.info(e)

                            if device.cu.commit_check():
                                try:
                                    r.hmset(facts['device_sn'], {'config': 'compliant'})
                                    logger.info('Commit confirmed.')
                                except Exception as e:
                                    logger.info(e)

                    except Exception as e:
                        logger.info(str(e))
                        r.hmset(facts['device_sn'], {'config': 'device lost'})
                        return
                else:
                    r.hmset(facts['device_sn'], {'config': 'commit check failed'})
                    logger.info('Commit check failed...')
                    device.cu.unlock()
                    try:
                        os.remove(config_file_location)
                    except Exception as e:
                        logger.error(f'Unable to delete {config_file_location}')
                        logger.error(str(e))

            except CommitError as err:
                logger.info("Unable to commit configuration: {0}".format(err))
                logger.info("Unlocking the configuration")
                try:
                    device.cu.unlock()
                except UnlockError as err:
                    logger.info("Unable to unlock configuration: {0}".format(err))

                try:
                    os.remove(config_file_location)
                except Exception as e:
                    logger.error(f'Unable to delete {config_file_location}')
                    logger.error(str(e))

                device.close()
                return

        logger.info("Unlocking the configuration")
        try:
            device.cu.unlock()
        except UnlockError as err:
            logger.info("Unable to unlock configuration: {0}".format(err))
            device.close()
        logger.info("Removing local config file")

        try:
            os.remove(config_file_location)
            logger.info("Config removed.")
        except Exception as e:
            logger.error(f'Unable to delete {config_file_location}')
            logger.error(str(e))

    else:
        logger.info(f'Config was not found for {facts["device_sn"]}')
        r.hmset(facts['device_sn'], {'configpy-node_error': 'Could not locate config in configs/'})
        r.hmset(facts['device_sn'], {'config': 'repo error'})

    # device.close()
    
    return
    

def gather_basic_facts(device, r):
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
    basic_facts['os_version'] = device.facts['version']
    basic_facts['device_sn'] = device.facts['serialnumber']
    
    if device.facts['model'] is None:
        basic_facts['device_model'] = 'cluster?'
        logger.info('No model - possible cluster')
    else:
        basic_facts['device_model'] = device.facts['model']
    
    if device.facts['hostname'] is None:
        basic_facts['hostname'] = 'no_hostname'
        logger.info('No hostname')
    else:
        basic_facts['hostname'] = device.facts['hostname']

    # FIXME - Likely a better way to handle this error if contact is not found.
    # Get SNMP contact ID:
    try:
        # Look for SNMP contact in config.
        config = device.rpc.get_config(filter_xml='snmp', options={'format':'json'})
        basic_facts['cid'] = config['configuration']['snmp']['contact']
        logger.info('A CID was found in the device config')

    except IndexError:
        logger.info('No CID found in the device config')
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
                logger.info('found ZTP flag!')
                logger.info(f'setting CID value to {str(ztp)}')
            else:
                # Shouldn't be used, but just in case.
                logger.info('No ZTP flag set in redis')
                basic_facts['cid'] = 'none'
        except KeyError:
            # ztp isn't a valid key, so no ztp.
            logger.info('Exception..setting CID to none.')
            basic_facts['cid'] = 'none'
    except Exception as e:
        # Catch anything else here...
        # Shouldn't be hit.
        basic_facts['cid'] = 'none'
        logger.info('Error when searching for CID')
        logger.info('ZTP not checked')
        logger.info('Error: {0}'.format(e))


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


class OutboundSSHServer(object):

    NAME = 'outbound-ssh-server'
    DEFAULT_LISTEN_BACKLOG = 10
    logger = logger

    def __init__(self, ipaddr, port, login_user, login_password, redis_url, repo_uri, repo_auth_token, on_device=None, on_error=None, unittest=None):
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
        self.redis_url = redis_url
        self.repo_uri = repo_uri
        self.repo_auth_token = repo_auth_token
        self.bind_ipaddr = ipaddr
        self.bind_port = int(port)
        self.listen_backlog = OutboundSSHServer.DEFAULT_LISTEN_BACKLOG

        self._callbacks = dict()

        self.on_device = on_device      # callable also provided at :meth:`start`
        self.on_error = on_error        # callable also provided at :meth:`start`

        self.r = redis.Redis(host=redis_url, port=6379, db=0)


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
            logger.error(f'{self.name}: failed to setup socket: %s' % str(exc))
            return

        while True:

            # await a device to make an outbound connection.  The socket accept() returns a tuple
            # (socket, (device ipaddr, device port)).  create a new thread to process the inbound with
            # this information

            try:
                in_sock, (in_addr, in_port) = self.socket.accept()

            except ConnectionAbortedError:
                # this triggers when the server socket is closed by the shutdown() method
                logger.info(f'{self.name} shutting down')
                return

            in_str = f'{in_addr}:{in_port}'
            dev_name = f'device-{in_str}'
            logger.info(f'{self.name}: accepted connection from {in_str}')

            # spawn a device-specific thread for further processing

            try:
                Thread(name=dev_name, target=self._device_thread,
                       kwargs=dict(in_sock=in_sock, in_addr=in_addr, in_port=in_port)).start()

            except RuntimeError as exc:
                logger.err(f'{self.name}: ERROR: failed to start processing {in_addr}: %s' % str(exc))
                in_sock.close()
                continue

        # NOT REACHABLE
        logger.critical('Unreachable code reached')

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
            logger.info(f"establishing netconf to device via: {via_str}")
            dev = Device(sock_fd=sock_fd, user=self.login_user, password=self.login_password)
            dev.open()

        except ConnectError as exc:
            logger.error(f'Connection error to device via {via_str}: {exc.msg}')
            in_sock.close()
            return

        except Exception as exc:
            logger.error(f'unable to establish netconf to device via {via_str}: {str(exc)}')
            in_sock.close()

        try:
            logger.info(f"gathering basic facts from device via: {via_str}")
            facts = gather_basic_facts(dev, self.r)
            logger.info(json.dumps(facts, indent=3))

            current_time = str(datetime.now().time())
            no_sec = current_time.split('.')
            poll = no_sec.pop(0)

            try:
                facts = convert(facts)
                self.r.hmset(facts['device_sn'], facts)
                self.r.hmset(facts['device_sn'], {'Last seen': poll})
                self.r.expire(facts['device_sn'], 300)
                logger.info(f'database for {facts["device_sn"]} will expire in 5 min.')
            except Exception as e:
                logger.info(e)

            ########################################

            update_config(dev, facts, self.r, self.repo_uri, self.repo_auth_token)
            logger.info('Config audit complete.')

            # call user on-device callback
            # self.on_device(dev, facts)

            logger.info(f"completed device with management IP address: {facts['mgmt_ipaddr']}")

            dev.close()
            logger.info('- ' * 30)

        except Exception as exc:
            error = f"ERROR: unable to process device {in_addr}:{in_port}: %s" % str(exc)
            logger.error(error)
            if self.on_error:
                self.on_error(dev, exc)

        finally:
            in_sock.close()

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
            logger.error(msg)
            return False, msg

        if on_device:
            self.on_device = on_device

        if on_error:
            self.on_error = on_error

        logger.info(f'{self.name}: starting on {self.bind_ipaddr}:{self.bind_port}')

        try:
            self.thread = Thread(name=self.name, target=self._server_thread)
            self.thread.start()

        except Exception as exc:
            msg = f'{self.name} unable to start: %s' % str(exc)
            logger.error(msg)
            return False, msg

        msg = f'{self.name}: started'
        logger.info(msg)
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
        logger.info(f'{self.name}: stopped')
