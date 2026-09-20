import io
import os
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from asa_cli_emulator import AsaCli, InterfaceInfo, LinuxArpEntry, LinuxConnection, LinuxDnsServer, run_linux_packet_tracer_probe, run_tcp_port_test, start_linux_packet_capture


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

    def test_packet_tracer_interface_completion_uses_canonical_prefix(self):
        self.cli._cmd_enable()
        completed, suggestions = self.cli._complete_line("packet-tracer input gig")
        self.assertEqual("packet-tracer input GigabitEthernet", completed)
        self.assertEqual(2, len(suggestions))

    def test_raw_terminal_newline_resets_the_cursor_column(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.cli._write_raw_newline()
        self.assertEqual("\r\n", output.getvalue())

    def test_ping_uses_linux_count_syntax(self):
        with patch("asa_cli_emulator.run_command", return_value="PING reply") as run:
            self.cli._dispatch_line("ping 192.0.2.1 2")
        run.assert_called_once_with(["ping", "-c", "2", "192.0.2.1"])

    def test_trace_route_uses_linux_traceroute(self):
        with patch("asa_cli_emulator.shutil.which", return_value="/usr/bin/traceroute"):
            with patch("asa_cli_emulator.run_command", return_value="trace") as run:
                self.cli._dispatch_line("trace route example.com 8")
        run.assert_called_once_with(["traceroute", "-n", "-m", "8", "-w", "1", "example.com"])

    def test_port_tester_uses_tcp_socket(self):
        with patch("asa_cli_emulator.run_tcp_port_test", return_value=(True, "TCP connection succeeded.")) as run:
            output = io.StringIO()
            with redirect_stdout(output):
                self.cli._dispatch_line("port tester example.com 443")
        run.assert_called_once_with("example.com", 443)
        self.assertIn("Port 443 on example.com is reachable.", output.getvalue())

    def test_tcp_port_test_uses_builtin_socket(self):
        connection = MagicMock()
        with patch("asa_cli_emulator.socket.create_connection", return_value=connection) as connect:
            self.assertEqual((True, "TCP connection to example.com:443 succeeded."), run_tcp_port_test("example.com", 443))
        connect.assert_called_once_with(("example.com", 443), timeout=5)

    def test_packet_tracer_collects_tcpdump_and_netfilter_diagnostics(self):
        tcpdump_process = MagicMock()
        nft_process = MagicMock()

        def which(command):
            return {"tcpdump": "/usr/sbin/tcpdump", "nft": "/usr/sbin/nft"}.get(command)

        with patch("asa_cli_emulator.is_admin", return_value=True):
            with patch("asa_cli_emulator.shutil.which", side_effect=which):
                with patch("asa_cli_emulator.run_command", return_value="route via 10.0.0.1"):
                    with patch("asa_cli_emulator.get_linux_packet_tracer_socket_snapshot", side_effect=["before socket", "after socket"]):
                        with patch("asa_cli_emulator.start_linux_packet_capture", return_value=tcpdump_process) as start_capture:
                            with patch("asa_cli_emulator.start_nft_trace_monitor", return_value=nft_process):
                                with patch("asa_cli_emulator.run_linux_packet_tracer_probe", return_value=(True, "Generated TCP probe.")) as probe:
                                    with patch("asa_cli_emulator.stop_linux_capture_process", side_effect=["tcpdump packet", "nft trace event"]) as stop:
                                        with patch("asa_cli_emulator.time.sleep"):
                                            output = io.StringIO()
                                            with redirect_stdout(output):
                                                self.cli._dispatch_line("packet-tracer input GigabitEthernet1/0 tcp 10.0.0.10 0 198.51.100.1 443 detailed")
        start_capture.assert_called_once_with("eth0", "tcp", "198.51.100.1", 443, True)
        probe.assert_called_once_with("tcp", "10.0.0.10", 0, "198.51.100.1", 443)
        self.assertEqual(tcpdump_process, stop.call_args_list[0].args[0])
        self.assertEqual(nft_process, stop.call_args_list[1].args[0])
        rendered = output.getvalue()
        self.assertIn("tcpdump packet", rendered)
        self.assertIn("nft trace event", rendered)

    def test_linux_packet_tracer_probe_binds_source_and_connects_tcp(self):
        probe_socket = MagicMock()
        with patch("asa_cli_emulator.socket.socket", return_value=probe_socket) as create_socket:
            self.assertEqual(
                (True, "Generated TCP probe to 198.51.100.1:443."),
                run_linux_packet_tracer_probe("tcp", "10.0.0.10", 12345, "198.51.100.1", 443),
            )
        create_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        probe_socket.__enter__.return_value.bind.assert_called_once_with(("10.0.0.10", 12345))
        probe_socket.__enter__.return_value.connect.assert_called_once_with(("198.51.100.1", 443))

    def test_linux_packet_capture_uses_scoped_tcpdump_filter(self):
        process = MagicMock()
        with patch("asa_cli_emulator.subprocess.Popen", return_value=process) as popen:
            self.assertEqual(process, start_linux_packet_capture("eth0", "tcp", "198.51.100.1", 443, True))
        popen.assert_called_once_with(
            ["tcpdump", "-nn", "-l", "-vvv", "-i", "eth0", "--", "tcp and host 198.51.100.1 and port 443"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

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
