import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from asa_cli_emulator import AsaCli, InterfaceInfo, StaticRoute, WindowsArpEntry, WindowsConnection, WindowsDnsServer


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
        self.assertEqual("interface GigabitEthernet", completed)
        self.assertEqual(2, len(suggestions))

    def test_show_run_interface_tab_completion_uses_canonical_prefix(self):
        self.cli._cmd_enable()
        completed, suggestions = self.cli._complete_line("show run interface gig")
        self.assertEqual("show run interface GigabitEthernet", completed)
        self.assertEqual(2, len(suggestions))

    def test_ping_invokes_windows_ping_with_repeat_count(self):
        with patch("asa_cli_emulator.run_command", return_value="Ping reply") as run:
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("ping 192.0.2.1 2")
        run.assert_called_once_with(["ping", "-n", "2", "192.0.2.1"])
        self.assertIn("Ping reply", output.getvalue())

    def test_trace_route_invokes_windows_tracert_with_hop_limit(self):
        with patch("asa_cli_emulator.run_command", return_value="Trace output") as run:
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("trace route example.com 8")
        run.assert_called_once_with(["tracert", "-d", "-h", "8", "-w", "1000", "example.com"])
        self.assertIn("Trace output", output.getvalue())

    def test_show_arp_renders_windows_neighbor_with_asa_interface_name(self):
        entries = [WindowsArpEntry("192.0.2.1", "001122334455", "Reachable", "Ethernet")]
        with patch("asa_cli_emulator.get_windows_arp_entries", return_value=entries):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show arp")
        rendered = output.getvalue()
        self.assertIn("192.0.2.1", rendered)
        self.assertIn("0011.2233.4455", rendered)
        self.assertIn("GigabitEthernet1/0", rendered)

    def test_show_processes_cpu_usage_accepts_asa_modifiers(self):
        processes = [{"ProcessName": "cpu-heavy", "Id": 101, "CpuPercent": 25.0, "WorkingSetMB": 64.0}]
        with patch("asa_cli_emulator.get_top_cpu_processes", return_value=processes):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show processes cpu-usage non-zero sorted")
        rendered = output.getvalue()
        self.assertIn("5Sec", rendered)
        self.assertIn("cpu-heavy", rendered)

    def test_show_conn_renders_windows_connection_with_asa_interface_name(self):
        connections = [WindowsConnection("TCP", "10.0.0.10", 50000, "198.51.100.1", 443, "Established", 1234)]
        with patch("asa_cli_emulator.get_windows_connections", return_value=connections):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show conn")
        rendered = output.getvalue()
        self.assertIn("10.0.0.10:50000", rendered)
        self.assertIn("GigabitEthernet1/0", rendered)
        self.assertIn("Established", rendered)

    def test_show_conn_combines_protocol_address_port_state_and_detail_filters(self):
        connections = [
            WindowsConnection("TCP", "10.0.0.10", 50000, "198.51.100.1", 443, "Established", 1234),
            WindowsConnection("UDP", "10.0.0.10", 5353, "224.0.0.251", 5353, "ACTIVE", 4321),
        ]
        with patch("asa_cli_emulator.get_windows_connections", return_value=connections):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line(
                    "show conn protocol tcp address 198.51.100.1 port 443 state up detail"
                )
        rendered = output.getvalue()
        self.assertIn("198.51.100.1:443", rendered)
        self.assertIn("traffic counters: unavailable", rendered)
        self.assertNotIn("224.0.0.251", rendered)

    def test_show_conn_protocol_completion_suggests_supported_protocols(self):
        completed, suggestions = self.cli._complete_line("show conn protocol ")
        self.assertEqual("show conn protocol ", completed)
        self.assertEqual(["tcp", "udp"], suggestions)

    def test_show_dns_renders_configured_windows_dns_servers(self):
        servers = [WindowsDnsServer("Ethernet", "1.1.1.1")]
        with patch("asa_cli_emulator.get_windows_dns_servers", return_value=servers):
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("show dns trusted-source detail")
        rendered = output.getvalue()
        self.assertIn("1.1.1.1", rendered)
        self.assertIn("GigabitEthernet1/0", rendered)
        self.assertIn("Ethernet", rendered)

    def test_show_output_redirection_writes_to_current_directory(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.cli._dispatch_line("show hostname > system.txt")
        self.assertEqual(f"{self.cli.hostname}\n", Path("system.txt").read_text(encoding="utf-8"))
        self.assertIn("Output written to system.txt", output.getvalue())

    def test_output_redirection_rejects_paths_outside_current_directory(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.cli._dispatch_line("show hostname > ..\\system.txt")
        self.assertIn("current directory", output.getvalue())
        self.assertFalse(Path("..", "system.txt").exists())

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
