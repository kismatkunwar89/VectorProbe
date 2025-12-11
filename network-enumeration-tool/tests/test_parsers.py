Here are the contents for the file /network-enumeration-tool/network-enumeration-tool/tests/test_parsers.py:

import unittest
from src.parsers.nmap_parser import parse_nmap_output
from src.parsers.smb_parser import parse_smb_output
from src.parsers.netbios_parser import parse_netbios_output

class TestNmapParser(unittest.TestCase):
    def test_parse_nmap_output(self):
        sample_output = """
        Nmap scan report for 192.168.1.1
        Host is up (0.0010s latency).
        Not shown: 999 closed ports
        PORT     STATE SERVICE
        22/tcp open  ssh
        80/tcp open  http
        """
        expected_result = {
            'ip': '192.168.1.1',
            'services': [
                {'port': 22, 'protocol': 'tcp', 'service': 'ssh'},
                {'port': 80, 'protocol': 'tcp', 'service': 'http'}
            ]
        }
        result = parse_nmap_output(sample_output)
        self.assertEqual(result, expected_result)

class TestSmbParser(unittest.TestCase):
    def test_parse_smb_output(self):
        sample_output = """
        Domain Name: WORKGROUP
        Computer Name: TEST-PC
        """
        expected_result = {
            'domain': 'WORKGROUP',
            'computer_name': 'TEST-PC'
        }
        result = parse_smb_output(sample_output)
        self.assertEqual(result, expected_result)

class TestNetbiosParser(unittest.TestCase):
    def test_parse_netbios_output(self):
        sample_output = """
        Name               Type         Status
        ---------------------------------------------
        TEST-PC           <00>  UNIQUE  Registered
        """
        expected_result = {
            'name': 'TEST-PC',
            'type': 'UNIQUE',
            'status': 'Registered'
        }
        result = parse_netbios_output(sample_output)
        self.assertEqual(result, expected_result)

if __name__ == '__main__':
    unittest.main()