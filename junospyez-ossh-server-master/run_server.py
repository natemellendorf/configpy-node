from junospyez_ossh_server import OutboundSSHServer
import logging
import argparse
from pprint import pprint
import json


def start(args):
    try:
        server = OutboundSSHServer(args.ip,
                                   port=args.port,
                                   login_user=args.user,
                                   login_password=args.password,
                                   configpy_url=args.configpy_url,
                                   redis_url=args.redis_url,
                                   repo_uri=args.repo_uri,
                                   repo_auth_token=args.repo_auth_token,
                                   software_location=args.software_location,
                                   srx_firmware=args.srx_firmware,
                                   srx_firmware_checksum=args.srx_firmware_checksum
                                   )

        # Enable logging to console
        server.logger.setLevel(logging.INFO)
        server.logger.addHandler(logging.StreamHandler())

        # Attempt to run ConfigPy-Node
        server.start()

    except Exception as e:
        # If en exception is raised, print the exception to th console.
        print(e)


if __name__ == '__main__':

    # Leverage argparse to validate and store arguments passed to the script.
    parser = argparse.ArgumentParser(description='configpy-node')
    parser.add_argument('-ip', default='0.0.0.0',  help='IP address to listen on.', required=False)
    parser.add_argument('-port', default='9000', help='TCP port to listen on.', required=False)
    parser.add_argument('-user', help='Username used to login to Junos devices.', required=True)
    parser.add_argument('-password', help='Password used ot login to Junos devices.', required=True)
    parser.add_argument('-configpy_url', help='Full URL to configpy WebUI.', required=True)
    parser.add_argument('-redis_url', help='FQDN of your IP of Redis DB/container.', required=True)
    parser.add_argument('-repo_uri', help='URI to your GitLab repository which houses your configs.', required=True)
    parser.add_argument('-repo_auth_token', help='Authentication token to access your GitLab API.', required=True)
    parser.add_argument('-software_location', help='URL or IP to a folder which houses your Junos firmware.', required=True)
    parser.add_argument('-srx_firmware', help='Exact name of the firmware file stored on the -software_location for the SRX300 series.', required=True)
    parser.add_argument('-srx_firmware_checksum', help='MD5 checksum for srx_firmware.', required=True)

    # Parse the arguments provided, and store them in the args var.
    args = parser.parse_args()

    try:
        # Pass the arguments provided to the start function, which will attempt to start the server.
        start(args)

    except Exception as e:
        # If any exception is raised, store the output as var e and then print it to the console.
        print(e)
