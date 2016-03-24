"""
This script is written for SSH connections to Cisco IOS devices. The user
privilege mode should be 15 for running commands in the correct user context
right after logging in.

SSHClient.py will
...ask the user for username and password input.
...create try to establish a SSH connection to all IP addresses listed in
 'DeviceList.csv'.
...run all commands listed in 'CommandList.csv' against every established
 SSH connection.
...write the output of each SSH connection to a file per session, including
 the Hostname, which is extracted from the SSH prompt (e.g. 'router out of
 SSH prompt 'router#')

Important notes:
Since the script will ask for one pair of credentials, all accessed devices
need to allow access to the same username/password combination.
"""

import os
import time
import getpass
import logging
import logging.config
from datetime import datetime
import textwrap
# Paramiko is not a Python standard module -> pip install Paramiko
import paramiko

# Change working directory to the scripts base directory
os.chdir(os.path.dirname(os.path.realpath(__file__)))

logcfgfile = 'logging.conf'

logging.config.fileConfig(logcfgfile)
logger = logging.getLogger('SSHClient')

# Ask user for SSH username and password input
user = input('Enter Username: ')
password = getpass.getpass('Enter Password: ')

# Name of the IP/Hostname address list file
devicefile = 'DeviceList.csv'
logger.info('Device File Name is: %s' % devicefile)

# Name of the IOS commands list file
commandfile = 'CommandList.csv'

# Filename suffix of the output file(s)
outputfilesuffix = '.txt'
# Grabbing current datetime into variable 'dt'
dt = datetime.now()
# Setting datetime format for output filename. Format: YYYYMMDD_hh-mm-ss
# Example: 20160307_12-30-00
dtstring = dt.strftime("%Y%m%d") + '_' + dt.strftime("%H-%M-%S")


def nopaging(sshsession):
    """
    The 'nopaging' function will execute IOS command 'terminal length 0' to
    the current SSH session and flush the output buffer. The command disables
    output paging to the SSH session, allowing output longer than one page to
    print to the SSH session without required user input.

    :param sshsession: SSH client session after connecting to the device in
     function 'sendcommand'
    :return: Nothing to return
    """
    # Send 'terminal length 0' to SSH session
    sshsession.send('term len 0\n')
    # Wait 1 seccond for command execution
    time.sleep(1)
    # Flush output buffer
    sshsession.recv(1000)
    return

def sendcommand(sshclient, ip, user, password, commands):
    """
    The 'sendcommand' function will establish a SSH connection to the IP
    address provided, send the list of commands specified in the 'commands'
    list object, extract the devices hostname from the IOS devices prompt
    and return the hostname and output.
    The output buffer might be adjusted to longer SSH outputs. Same counts
    for the sleep timer after each command. Output from commands like
    'show tech' might need longer sleep timers.

    :param sshclient: SSH connection created as Paramiko SSHClient object.
    :param ip: Current IP address from device list.
    :param user: IOS username from user input.
    :param password: IOS password from user input.
    :param commands: IOS commands list as list object
    :return: Returning extracted IOS hostname and SSH output
    """

    # Trying to establish the SSH session, using a timeout of 3 seconds
    sshclient.connect(ip, username=user, password=password,
                      look_for_keys=False, allow_agent=False, timeout=3)
    # To execute commands we'll need an input shell to execute them against
    sshsession = sshclient.invoke_shell()
    # Read current output buffer for hostname extraction.
    # Expected is something like 'hostname#'
    hostname = sshsession.recv(1000)
    # Decode output to UTF-8 encoding
    hostname = hostname.decode('utf-8')
    # Replace whitespaces and the expected '#' from the prompt with nothing
    hostname = hostname.replace('\r\n', '').replace('#', '')
    # Execute 'nopaging' function to disable paging
    nopaging(sshsession)
    # Run each command in commands list against the current session, using
    # a sleep timer of 3s after each command.
    for command in commands:
        command = textwrap.wrap(command)[0]
        sshsession.send(command)
        # Don't forget to press 'Enter' after each command. This will do.
        sshsession.send('\n')
        # Might need more time for commands like 'show tech' but 3s should
        # do fine for most outputs.
        time.sleep(3)

    # Flush current output into output variable. Might need adjustment for
    # larger outputs.
    output = sshsession.recv(100000)
    # Say goodbye to the device.
    sshclient.close()

    # Return the SSH output and extracted hostname
    return output, hostname

def outputtofile(filename, output):
    """
    This function writes output to a textfile.

    :param filename: Name of the output file.
    :param output: Output
    :return: Nothing to return.
    """

    # Open outputfile in write mode, create if it doesn't exist. The with
    # statement of 'open' will take care of closing the file afterwards.
    with open(filename, 'w') as f:
        # Decode output string to UTF-8
        output = output.decode('utf-8')
        # Write all output to the file
        f.write(output)
        return

# Create a Paramiko SSHClient object that will be used for each SSH session
sshclient = paramiko.SSHClient()
# Set the SSHClient properties to accept connections to devices without
# having the appropriate SSH key ready.
sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Read all commands into a list object by opening the command list file and
    # extracting line by line out of it.
    with open(commandfile, 'r') as f:
        commands = f.readlines()

    # Open the device file list in read mode.
    with open(devicefile, 'r') as f:
        # 'f.readlines' reads all IPs/Hostnames from the device list into a list
        # object. 'For l in' executes the following commands for each list entry,
        # so for each IP/Hostname from the file.
        for l in f.readlines():
            # Strip whitespace characters from the current entry and fill
            # variable ip with the result.
            ip = textwrap.wrap(l)[0]

            try:
                # Run the SSH commands list object against the current device
                # IP/Hostname by using function 'sendcommand'
                output, hostname = sendcommand(sshclient, ip, user, password, commands)

                # Setting output filename based on the devices hostname, datetimestring
                # and file suffix
                outputfile = hostname + '_' + dtstring + outputfilesuffix

                # Write the output to file through function 'outputtofile'
                outputtofile(outputfile, output)
            except Exception as e:
                logger.error('Error while connecting to: %s - %s' %(ip,e))

except Exception as e:
    logger.fatal('A fatal error occurred: %s' %e)