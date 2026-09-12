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

    def test_show_interface_renders_selected_adapter_only(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.cli._dispatch_line("show interface gigabitethernet1/0")
        rendered = output.getvalue()
        self.assertIn('Interface GigabitEthernet1/0 "GigabitEthernet1/0"', rendered)
        self.assertIn("Windows adapter: Ethernet", rendered)
        self.assertNotIn("GigabitEthernet2/0", rendered)

    def test_show_cpu_detail_displays_top_processes(self):
        processes = [{"ProcessName": "cpu-heavy", "Id": 100, "CpuPercent": 42.5, "WorkingSetMB": 128.0}]
        with patch("asa_cli_emulator.get_top_cpu_processes", return_value=processes):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show cpu detail 1")
        self.assertIn("Top 1 processes by sampled CPU utilization", output.getvalue())
        self.assertIn("cpu-heavy", output.getvalue())

    def test_show_memory_detail_displays_top_processes(self):
        processes = [{"ProcessName": "memory-heavy", "Id": 200, "WorkingSetMB": 512.0, "PagedMemoryMB": 256.0, "Handles": 12}]
        with patch("asa_cli_emulator.get_top_memory_processes", return_value=processes):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show mem detail 1")
        self.assertIn("Top 1 processes by working-set memory", output.getvalue())
        self.assertIn("memory-heavy", output.getvalue())

    def test_show_run_interface_only_displays_interface_configuration(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.cli._dispatch_line("show run int")
        rendered = output.getvalue()
        self.assertIn("interface GigabitEthernet1/0", rendered)
        self.assertNotIn("ASA Version", rendered)
        self.assertNotIn("service-policy", rendered)

    def test_show_run_route_only_displays_route_configuration(self):
        self.cli.static_routes.append(
            StaticRoute("GigabitEthernet1/0", "198.51.100.0", "255.255.255.0", "10.0.0.1", 1)
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.cli._dispatch_line("show run route")
        rendered = output.getvalue()
        self.assertIn("route GigabitEthernet1/0 198.51.100.0", rendered)
        self.assertNotIn("interface GigabitEthernet", rendered)


if __name__ == "__main__":
    unittest.main()
