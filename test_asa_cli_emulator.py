import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from asa_cli_emulator import AsaCli, InterfaceInfo, StaticRoute


def sample_interfaces():
    return [
        InterfaceInfo(
            name="Ethernet",
            mac_address="00-11-22-33-44-55",
            ipv4_addresses=["10.0.0.10"],
            dhcp_enabled="Yes",
        ),
        InterfaceInfo(
            name="Ethernet 2",
            mac_address="00-11-22-33-44-66",
            ipv4_addresses=["192.168.1.10"],
            dhcp_enabled="No",
        ),
    ]


class AsaCliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.previous_directory = os.getcwd()
        os.chdir(self.tempdir.name)
        self.parse_patch = patch("asa_cli_emulator.parse_ipconfig", return_value=sample_interfaces())
        self.parse_patch.start()
        self.cli = AsaCli()

    def tearDown(self):
        self.parse_patch.stop()
        os.chdir(self.previous_directory)
        self.tempdir.cleanup()

    def enter_interface_mode(self):
        self.cli._cmd_enable()
        self.cli._cmd_configure_terminal()
        self.cli._dispatch_line("interface gigabitethernet1/0")

    def test_tab_completion_uses_shared_interface_prefix(self):
        self.cli._cmd_enable()
        self.cli._cmd_configure_terminal()
        completed, suggestions = self.cli._complete_line("interface gig")
        self.assertEqual("interface gigabitethernet", completed)
        self.assertEqual(2, len(suggestions))

    def test_invalid_dhcp_suffix_does_not_apply(self):
        self.enter_interface_mode()
        with patch.object(self.cli, "_apply_dhcp_ip") as apply_dhcp:
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("ip address dhcp unexpected")
        apply_dhcp.assert_not_called()
        self.assertIn("Invalid IP address", output.getvalue())

    def test_write_memory_creates_startup_snapshot(self):
        self.cli.hostname = "saved-host"
        self.cli._cmd_write_memory()
        self.assertTrue(Path(".asa-cli-emulator-config.json").exists())
        self.cli.hostname = "changed-host"
        output = io.StringIO()
        with redirect_stdout(output):
            self.cli._dispatch_line("show startup-config")
        self.assertIn("hostname saved-host", output.getvalue())
        self.assertNotIn("hostname changed-host", output.getvalue())

    def test_failed_route_metric_update_restores_original_route(self):
        self.cli.static_routes = [
            StaticRoute("GigabitEthernet1/0", "198.51.100.0", "255.255.255.0", "10.0.0.1", 1)
        ]
        with patch.object(self.cli, "_apply_route", side_effect=[True, False, True]) as apply_route:
            self.cli._configure_route(
                ["route", "gigabitethernet1/0", "198.51.100.0", "255.255.255.0", "10.0.0.1", "20"],
                negate=False,
            )
        self.assertEqual(1, self.cli.static_routes[0].metric)
        self.assertEqual(3, apply_route.call_count)

    def test_sanitized_tech_masks_identifiers(self):
        self.cli.hostname = "private-host"
        self.cli.username = "private-user"
        output = self.cli._sanitize_tech_output(
            "private-host private-user 10.0.0.10 00-11-22-33-44-55\nWorking Dir     : C:\\Users\\private-user"
        )
        self.assertNotIn("private-host", output)
        self.assertNotIn("private-user", output)
        self.assertNotIn("10.0.0.10", output)
        self.assertNotIn("00-11-22-33-44-55", output)


if __name__ == "__main__":
    unittest.main()
