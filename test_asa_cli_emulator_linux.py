import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from asa_cli_emulator import AsaCli, InterfaceInfo, LinuxArpEntry, LinuxConnection, LinuxDnsServer


def sample_linux_interfaces():
    return [
        InterfaceInfo(
            name="eth0",
            mac_address="00:11:22:33:44:55",
            ipv4_addresses=["10.0.0.10"],
            dhcp_enabled="No",
        ),
        InterfaceInfo(
            name="wlan0",
            mac_address="00:11:22:33:44:66",
            ipv4_addresses=["192.168.1.10"],
            dhcp_enabled="No",
        ),
    ]


class LinuxAsaCliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.previous_directory = os.getcwd()
        os.chdir(self.tempdir.name)
        self.interface_patch = patch("asa_cli_emulator.parse_linux_interfaces", return_value=sample_linux_interfaces())
        self.interface_patch.start()
        self.cli = AsaCli()

    def tearDown(self):
        self.interface_patch.stop()
        os.chdir(self.previous_directory)
        self.tempdir.cleanup()

    def test_show_run_interface_completion_uses_canonical_name(self):
        self.cli._cmd_enable()
        completed, suggestions = self.cli._complete_line("show run interface gig")
        self.assertEqual("show run interface GigabitEthernet", completed)
        self.assertEqual(2, len(suggestions))

    def test_ping_uses_linux_count_syntax(self):
        with patch("asa_cli_emulator.run_command", return_value="PING reply") as run:
            self.cli._dispatch_line("ping 192.0.2.1 2")
        run.assert_called_once_with(["ping", "-c", "2", "192.0.2.1"])

    def test_trace_route_uses_linux_traceroute(self):
        with patch("asa_cli_emulator.shutil.which", return_value="/usr/bin/traceroute"):
            with patch("asa_cli_emulator.run_command", return_value="trace") as run:
                self.cli._dispatch_line("trace route example.com 8")
        run.assert_called_once_with(["traceroute", "-n", "-m", "8", "-w", "1", "example.com"])

    def test_show_arp_maps_linux_device_to_asa_interface(self):
        entries = [LinuxArpEntry("192.0.2.1", "001122334455", "REACHABLE", "eth0")]
        with patch("asa_cli_emulator.get_linux_arp_entries", return_value=entries):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show arp")
        rendered = output.getvalue()
        self.assertIn("0011.2233.4455", rendered)
        self.assertIn("GigabitEthernet1/0", rendered)

    def test_show_conn_applies_linux_filters(self):
        connections = [
            LinuxConnection("TCP", "10.0.0.10", 50000, "198.51.100.1", 443, "ESTAB", 1234),
            LinuxConnection("UDP", "10.0.0.10", 5353, "224.0.0.251", 5353, "UNCONN", 4321),
        ]
        with patch("asa_cli_emulator.get_linux_connections", return_value=connections):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show conn protocol tcp address 198.51.100.1 port 443 detail")
        rendered = output.getvalue()
        self.assertIn("198.51.100.1:443", rendered)
        self.assertIn("traffic counters: unavailable", rendered)
        self.assertNotIn("224.0.0.251", rendered)

    def test_show_dns_reads_linux_resolver_entries(self):
        servers = [LinuxDnsServer("system", "1.1.1.1")]
        with patch("asa_cli_emulator.get_linux_dns_servers", return_value=servers):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show dns trusted-source detail")
        self.assertIn("1.1.1.1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
