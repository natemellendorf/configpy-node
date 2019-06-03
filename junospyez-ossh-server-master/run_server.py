from junospyez_ossh_server import OutboundSSHServer
import logging
from sys import argv

error_message = 'Must run server with args:\r\npython run_server.py USERNAME PASSWORD REDIS_IP'

def start(**kwargs):
    if kwargs['login_user'] and kwargs['login_password'] and kwargs['redis_url']:
        server = OutboundSSHServer('0.0.0.0', port=9000,
                                   login_user=kwargs['login_user'],
                                   login_password=kwargs['login_password'],
                                   redis_url=kwargs['redis_url'],
                                   repo_uri=kwargs['repo_uri'],
                                   repo_auth_token=kwargs['repo_auth_token'],
                                   software_host=kwargs['software_host']
                                   )
        server.logger.setLevel(logging.INFO)
        server.logger.addHandler(logging.StreamHandler())
        server.start()
    else:
        print(error_message)


if __name__ == '__main__':
    # FIXME - Need to find a better way to handle args...
    if len(argv) == 7:
        try:
            start(login_user=argv[1], login_password=argv[2], redis_url=argv[3], repo_uri=argv[4], repo_auth_token=argv[5], software_host=argv[6])
        except Exception as e:
            print(e)
    else:
        print(error_message)
