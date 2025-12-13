import subprocess
import logging

class SMBHandler:
    def __init__(self, target):
        self.target = target

    def enumerate_smb_shares(self):
        """Enumerate SMB shares on the target."""
        try:
            command = f"smbclient -L {self.target} -N"
            logging.info(f"Running command: {command}")
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            logging.error(f"Error enumerating SMB shares: {e.output.decode('utf-8')}")
            return None

    def enumerate_smb_users(self):
        """Enumerate SMB users on the target."""
        try:
            command = f"smbclient -M {self.target} -N"
            logging.info(f"Running command: {command}")
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            logging.error(f"Error enumerating SMB users: {e.output.decode('utf-8')}")
            return None