import ctypes
import io
import json
import getpass
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    import msvcrt
except ImportError:
    msvcrt = None


def run_command(command: List[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return (completed.stdout or completed.stderr or "").strip()
    except OSError as exc:
        return f"Unable to run {' '.join(command)}: {exc}"


def run_ftp_port_test(host: str, port: int) -> str:
    """Use Windows FTP's open command as a TCP reachability probe."""
    try:
        completed = subprocess.run(
            ["ftp", "-n"],
            input=f"open {host} {port}\nquit\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        return (completed.stdout or completed.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return "FTP port test timed out."
    except OSError as exc:
        return f"Unable to run ftp: {exc}"


def run_live_command(command: List[str]) -> Tuple[bool, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        return False, str(exc)

    output = (completed.stdout or completed.stderr or "").strip()
    return completed.returncode == 0, output


def powershell(command: str) -> str:
    return run_command(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ]
    )


def clean_command_output(value: str) -> str:
    text = (value or "").strip()
    lowered = text.lower()
    if not text:
        return ""
    if "access denied" in lowered or "fullyqualifiederrorid" in lowered or "exception" in lowered:
        return ""
    return text


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def mask_to_prefix(mask: str) -> Optional[int]:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


@dataclass
class InterfaceInfo:
    name: str
    mac_address: str = "unassigned"
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    dhcp_enabled: Optional[str] = None
    status: str = "up"


def parse_ipconfig() -> List[InterfaceInfo]:
    output = run_command(["ipconfig", "/all"])
    if not output:
        return []

    interfaces: List[InterfaceInfo] = []
    current: Optional[InterfaceInfo] = None

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue

        header = re.match(
            r"^(?:Ethernet adapter|Wireless LAN adapter|Unknown adapter|PPP adapter|Tunnel adapter) (.+):$",
            stripped,
        )
        if header:
            if current:
                interfaces.append(current)
            current = InterfaceInfo(name=header.group(1))
            continue

        if current is None or ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        key = key.replace(".", "").strip().lower()
        value = value.strip()

        if key == "physical address":
            current.mac_address = value or "unassigned"
        elif key == "dhcp enabled":
            current.dhcp_enabled = value or None
        elif key.startswith("ipv4 address"):
            current.ipv4_addresses.append(value.replace("(Preferred)", "").strip())
        elif key.startswith("ipv6 address") or key.startswith("temporary ipv6 address") or key.startswith("link-local ipv6 address"):
            current.ipv6_addresses.append(value.replace("(Preferred)", "").strip())
        elif key == "media state" and "disconnected" in value.lower():
            current.status = "administratively down"

    if current:
        interfaces.append(current)

    return interfaces


def get_hostname() -> str:
    return socket.gethostname()


def get_domain() -> str:
    fqdn = socket.getfqdn()
    hostname = get_hostname()
    if fqdn and fqdn != hostname and "." in fqdn:
        return fqdn.split(".", 1)[1]
    return "WORKGROUP"


def get_primary_ipv4() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_os_caption() -> str:
    return f"{platform.system()} {platform.release()} build {platform.version()}"


def get_serial_number() -> str:
    serial = clean_command_output(powershell("(Get-CimInstance Win32_BIOS).SerialNumber"))
    return serial or "Unknown"


def get_model() -> str:
    model = clean_command_output(powershell("(Get-CimInstance Win32_ComputerSystem).Model"))
    return model or platform.node() or "Windows Device"


def get_manufacturer() -> str:
    manufacturer = clean_command_output(powershell("(Get-CimInstance Win32_ComputerSystem).Manufacturer"))
    return manufacturer or "Unknown"


def get_total_memory_gb() -> str:
    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(MemoryStatus)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return f"{status.ullTotalPhys / (1024 ** 3):.2f}"
    return "Unknown"


def get_memory_snapshot() -> Dict[str, float]:
    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return {}

    return {
        "load_percent": float(status.dwMemoryLoad),
        "total_gb": status.ullTotalPhys / (1024 ** 3),
        "available_gb": status.ullAvailPhys / (1024 ** 3),
        "used_gb": (status.ullTotalPhys - status.ullAvailPhys) / (1024 ** 3),
        "total_virtual_gb": status.ullTotalVirtual / (1024 ** 3),
        "available_virtual_gb": status.ullAvailVirtual / (1024 ** 3),
    }


def get_uptime_string() -> str:
    if hasattr(ctypes.windll.kernel32, "GetTickCount64"):
        milliseconds = ctypes.windll.kernel32.GetTickCount64()
        seconds = milliseconds // 1000
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, _ = divmod(seconds, 60)
        return f"{days} days, {hours} hours, {minutes} minutes"
    return "Unknown"


def get_cpu_snapshot(sample_seconds: float = 0.2) -> Dict[str, float]:
    class FileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

    def read_times() -> Optional[Tuple[int, int, int]]:
        idle = FileTime()
        kernel = FileTime()
        user = FileTime()
        ok = ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        if not ok:
            return None

        def to_int(value: FileTime) -> int:
            return (value.dwHighDateTime << 32) | value.dwLowDateTime

        return to_int(idle), to_int(kernel), to_int(user)

    start = read_times()
    if start is None:
        return {}
    ctypes.windll.kernel32.Sleep(int(sample_seconds * 1000))
    end = read_times()
    if end is None:
        return {}

    idle_delta = end[0] - start[0]
    kernel_delta = end[1] - start[1]
    user_delta = end[2] - start[2]
    total_delta = kernel_delta + user_delta
    if total_delta <= 0:
        return {}

    busy_percent = max(0.0, min(100.0, (1.0 - (idle_delta / total_delta)) * 100.0))
    return {
        "usage_percent": busy_percent,
        "logical_processors": float(os.cpu_count() or 0),
    }


def split_words(text: str) -> Tuple[List[str], bool]:
    trailing_space = bool(text) and text[-1].isspace()
    words = text.strip().split() if text.strip() else []
    return words, trailing_space


@dataclass
class CommandNode:
    help_text: str
    action: Optional[Callable[[], Optional[bool]]] = None
    children: Dict[str, "CommandNode"] = field(default_factory=dict)


@dataclass
class EmulatedInterface:
    asa_name: str
    windows_name: str
    mac_address: str
    live_ipv4: Optional[str]
    live_method: str
    description: str
    nameif: Optional[str] = None
    security_level: Optional[int] = None
    configured_ip: Optional[str] = None
    configured_mask: Optional[str] = None
    dhcp_enabled: bool = False
    dhcp_setroute: bool = False
    shutdown: bool = False

    def effective_ip(self) -> Optional[str]:
        return self.configured_ip or self.live_ipv4

    def effective_method(self) -> str:
        if self.dhcp_enabled:
            return "DHCP"
        return "manual" if self.configured_ip else self.live_method


@dataclass
class StaticRoute:
    interface_name: str
    destination: str
    mask: str
    gateway: str
    metric: int = 1


@dataclass
class WindowsRoute:
    destination: str
    mask: str
    gateway: str
    interface_ip: str
    metric: int


@dataclass
class WindowsArpEntry:
    address: str
    mac_address: str
    state: str
    interface_alias: str


def get_windows_ipv4_routes() -> List[WindowsRoute]:
    output = run_command(["route", "print", "-4"])
    routes: List[WindowsRoute] = []
    in_active_routes = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line == "Active Routes:":
            in_active_routes = True
            continue
        if line == "Persistent Routes:":
            break
        if not in_active_routes or not line or line.startswith("Network Destination"):
            continue

        parts = line.split()
        if len(parts) != 5:
            continue

        destination, mask, gateway, interface_ip, metric_text = parts
        if not _looks_like_ipv4(destination) or not _looks_like_ipv4(mask) or not _looks_like_ipv4(interface_ip):
            continue
        if gateway.lower() != "on-link" and not _looks_like_ipv4(gateway):
            continue

        try:
            metric = int(metric_text)
        except ValueError:
            continue

        routes.append(
            WindowsRoute(
                destination=destination,
                mask=mask,
                gateway=gateway,
                interface_ip=interface_ip,
                metric=metric,
            )
        )

    return routes or _get_windows_ipv4_routes_powershell()


def _get_windows_ipv4_routes_powershell() -> List[WindowsRoute]:
    output = clean_command_output(
        powershell(
            "$addressByIndex = @{}; "
            "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | "
            "Where-Object { $_.IPAddress -notlike '127.*' } | "
            "ForEach-Object { if (-not $addressByIndex.ContainsKey($_.InterfaceIndex)) { $addressByIndex[$_.InterfaceIndex] = $_.IPAddress } }; "
            "Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{DestinationPrefix=$_.DestinationPrefix; NextHop=$_.NextHop; InterfaceIp=$addressByIndex[$_.InterfaceIndex]; RouteMetric=$_.RouteMetric} } | "
            "ConvertTo-Json -Compress"
        )
    )
    if not output:
        return []

    try:
        values = json.loads(output)
    except json.JSONDecodeError:
        return []
    if isinstance(values, dict):
        values = [values]
    if not isinstance(values, list):
        return []

    routes: List[WindowsRoute] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        prefix = value.get("DestinationPrefix")
        gateway = value.get("NextHop")
        interface_ip = value.get("InterfaceIp")
        metric = value.get("RouteMetric")
        if not isinstance(prefix, str) or not isinstance(gateway, str) or not isinstance(interface_ip, str):
            continue
        try:
            network = ipaddress.IPv4Network(prefix, strict=False)
            route_metric = int(metric)
        except (ValueError, TypeError):
            continue
        routes.append(
            WindowsRoute(
                destination=str(network.network_address),
                mask=str(network.netmask),
                gateway="On-link" if gateway == "0.0.0.0" else gateway,
                interface_ip=interface_ip,
                metric=route_metric,
            )
        )
    return routes


def _looks_like_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def get_windows_arp_entries() -> List[WindowsArpEntry]:
    values = powershell_json_array(
        "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Json -Compress"
    )
    entries: List[WindowsArpEntry] = []
    for value in values:
        address = value.get("IPAddress")
        mac_address = value.get("LinkLayerAddress")
        state = value.get("State")
        interface_alias = value.get("InterfaceAlias")
        if not isinstance(address, str) or not _looks_like_ipv4(address):
            continue
        if not isinstance(mac_address, str) or not isinstance(interface_alias, str):
            continue
        compact_mac = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
        if len(compact_mac) != 12 or compact_mac == "000000000000":
            continue
        entries.append(
            WindowsArpEntry(
                address=address,
                mac_address=compact_mac.upper(),
                state=str(state or "Unknown"),
                interface_alias=interface_alias,
            )
        )
    return sorted(entries, key=lambda entry: (ipaddress.IPv4Address(entry.address), entry.interface_alias.lower()))


def powershell_json_array(command: str) -> List[Dict[str, object]]:
    output = clean_command_output(powershell(command))
    if not output:
        return []
    try:
        values = json.loads(output)
    except json.JSONDecodeError:
        return []
    if isinstance(values, dict):
        values = [values]
    return [value for value in values if isinstance(value, dict)] if isinstance(values, list) else []


def get_top_cpu_processes(limit: int = 10) -> List[Dict[str, object]]:
    return powershell_json_array(
        "$interval = 0.5; $before = @{}; "
        "Get-Process -ErrorAction SilentlyContinue | Where-Object { $null -ne $_.CPU } | "
        "ForEach-Object { $before[$_.Id] = $_.CPU }; "
        "Start-Sleep -Milliseconds 500; "
        "Get-Process -ErrorAction SilentlyContinue | Where-Object { $before.ContainsKey($_.Id) -and $null -ne $_.CPU } | "
        "ForEach-Object { [PSCustomObject]@{ProcessName=$_.ProcessName; Id=$_.Id; CpuPercent=[math]::Round((($_.CPU - $before[$_.Id]) / $interval / [Environment]::ProcessorCount) * 100, 1); WorkingSetMB=[math]::Round($_.WorkingSet64 / 1MB, 1)} } | "
        f"Sort-Object CpuPercent -Descending | Select-Object -First {limit} | ConvertTo-Json -Compress"
    )


def get_top_memory_processes(limit: int = 10) -> List[Dict[str, object]]:
    return powershell_json_array(
        "Get-Process -ErrorAction SilentlyContinue | "
        "Sort-Object WorkingSet64 -Descending | "
        f"Select-Object -First {limit} ProcessName,Id,@{{Name='WorkingSetMB';Expression={{[math]::Round($_.WorkingSet64 / 1MB, 1)}}}},@{{Name='PagedMemoryMB';Expression={{[math]::Round($_.PagedMemorySize64 / 1MB, 1)}}}},Handles | "
        "ConvertTo-Json -Compress"
    )


def get_windows_processes(limit: int = 100) -> List[Dict[str, object]]:
    return powershell_json_array(
        "Get-Process -ErrorAction SilentlyContinue | "
        "Sort-Object Id | "
        f"Select-Object -First {limit} ProcessName,Id,CPU,@{{Name='WorkingSetMB';Expression={{[math]::Round($_.WorkingSet64 / 1MB, 1)}}}},Handles | "
        "ConvertTo-Json -Compress"
    )


@dataclass
class WindowsConnection:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    owning_process: int


@dataclass(frozen=True)
class WindowsDnsServer:
    interface_alias: str
    address: str


@dataclass
class ConnectionFilters:
    show_all: bool = False
    detail: bool = False
    long_format: bool = False
    protocols: List[str] = field(default_factory=list)
    states: List[str] = field(default_factory=list)
    address_filters: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    port_filters: List[str] = field(default_factory=list)


def get_windows_connections() -> List[WindowsConnection]:
    values = powershell_json_array(
        "$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Where-Object { $_.State -ne 'Listen' } | "
        "ForEach-Object { [PSCustomObject]@{Protocol='TCP';LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;State=$_.State;OwningProcess=$_.OwningProcess} }; "
        "$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | "
        "ForEach-Object { [PSCustomObject]@{Protocol='UDP';LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress='0.0.0.0';RemotePort=0;State='ACTIVE';OwningProcess=$_.OwningProcess} }; "
        "@($tcp) + @($udp) | ConvertTo-Json -Compress"
    )
    connections: List[WindowsConnection] = []
    for value in values:
        try:
            protocol = str(value["Protocol"])
            local_address = str(value["LocalAddress"])
            local_port = int(value["LocalPort"])
            remote_address = str(value["RemoteAddress"])
            remote_port = int(value["RemotePort"])
            state = str(value["State"])
            owning_process = int(value["OwningProcess"])
        except (KeyError, TypeError, ValueError):
            continue
        connections.append(
            WindowsConnection(
                protocol=protocol,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                state=state,
                owning_process=owning_process,
            )
        )
    return sorted(connections, key=lambda item: (item.protocol, item.local_address, item.local_port, item.remote_address))


def get_windows_dns_servers() -> List[WindowsDnsServer]:
    values = powershell_json_array(
        "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses } | "
        "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress"
    )
    servers: List[WindowsDnsServer] = []
    for value in values:
        interface_alias = value.get("InterfaceAlias")
        addresses = value.get("ServerAddresses")
        if not isinstance(interface_alias, str):
            continue
        if isinstance(addresses, str):
            addresses = [addresses]
        if not isinstance(addresses, list):
            continue
        for address in addresses:
            if isinstance(address, str) and _looks_like_ipv4(address):
                servers.append(WindowsDnsServer(interface_alias=interface_alias, address=address))
    return sorted(set(servers), key=lambda item: (item.interface_alias.lower(), ipaddress.IPv4Address(item.address)))


class AsaCli:
    def __init__(self) -> None:
        self.hostname = self._sanitize_hostname(get_hostname())
        self.enabled = False
        self.config_submode = "exec"
        self.username = getpass.getuser()
        self.base_interfaces = parse_ipconfig()
        self.interfaces = self._build_emulated_interfaces(self.base_interfaces)
        self.current_interface: Optional[str] = None
        self.static_routes: List[StaticRoute] = self._build_default_routes()
        self.history: List[str] = []
        self._last_input_width = 0
        self.config_path = Path.cwd() / ".asa-cli-emulator-config.json"
        self.startup_config_text: Optional[str] = None
        self.user_tree, self.enabled_tree, self.config_tree, self.interface_tree = self._build_command_trees()
        self._load_saved_config()

    @staticmethod
    def _sanitize_hostname(name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_-]", "-", name.strip())
        return safe[:32] or "asa-emulator"

    @property
    def prompt(self) -> str:
        if self.config_submode == "config-if":
            return f"{self.hostname}(config-if)# "
        if self.config_submode == "config":
            return f"{self.hostname}(config)# "
        if self.enabled:
            return f"{self.hostname}# "
        return f"{self.hostname}> "

    def _build_emulated_interfaces(self, interfaces: List[InterfaceInfo]) -> Dict[str, EmulatedInterface]:
        mapped: Dict[str, EmulatedInterface] = {}
        for index, interface in enumerate(interfaces, start=1):
            asa_name = self._asa_interface_name(index, interface.name)
            live_ip = interface.ipv4_addresses[0] if interface.ipv4_addresses else None
            live_method = "DHCP" if (interface.dhcp_enabled or "").lower() == "yes" else "manual"
            mapped[asa_name.lower()] = EmulatedInterface(
                asa_name=asa_name,
                windows_name=interface.name,
                mac_address=interface.mac_address,
                live_ipv4=live_ip,
                live_method=live_method,
                description=f"Windows adapter: {interface.name}",
                dhcp_enabled=live_method == "DHCP",
                shutdown=interface.status == "administratively down",
            )
        return mapped

    def _build_default_routes(self) -> List[StaticRoute]:
        routes: List[StaticRoute] = []
        for interface in self.interfaces.values():
            if interface.effective_ip():
                routes.append(
                    StaticRoute(
                        interface_name=interface.asa_name,
                        destination=interface.effective_ip(),
                        mask="255.255.255.255",
                        gateway="0.0.0.0",
                        metric=0,
                    )
                )
        return routes

    def _config_snapshot(self) -> Dict[str, object]:
        return {
            "hostname": self.hostname,
            "interfaces": {
                key: {
                    "description": interface.description,
                    "nameif": interface.nameif,
                    "security_level": interface.security_level,
                    "configured_ip": interface.configured_ip,
                    "configured_mask": interface.configured_mask,
                    "dhcp_enabled": interface.dhcp_enabled,
                    "dhcp_setroute": interface.dhcp_setroute,
                    "shutdown": interface.shutdown,
                }
                for key, interface in self.interfaces.items()
            },
            "static_routes": [route.__dict__ for route in self.static_routes if route.metric != 0],
        }

    def _load_saved_config(self) -> None:
        if not self.config_path.exists():
            return
        try:
            saved = json.loads(self.config_path.read_text(encoding="utf-8"))
            config = saved.get("config", {})
            running_config = saved.get("running_config")
            if isinstance(running_config, str):
                self.startup_config_text = running_config
            hostname = config.get("hostname")
            if isinstance(hostname, str):
                self.hostname = self._sanitize_hostname(hostname)

            interface_configs = config.get("interfaces", {})
            if isinstance(interface_configs, dict):
                for key, values in interface_configs.items():
                    if key not in self.interfaces or not isinstance(values, dict):
                        continue
                    interface = self.interfaces[key]
                    for field_name in (
                        "description",
                        "nameif",
                        "security_level",
                    ):
                        if field_name in values:
                            setattr(interface, field_name, values[field_name])

            routes = config.get("static_routes", [])
            if isinstance(routes, list):
                self.static_routes = self._build_default_routes()
                for values in routes:
                    if not isinstance(values, dict):
                        continue
                    try:
                        self.static_routes.append(StaticRoute(**values))
                    except TypeError:
                        continue
        except (OSError, json.JSONDecodeError):
            print("% Warning: unable to load saved emulator configuration.")

    def _save_config(self) -> bool:
        payload = {
            "format_version": 1,
            "saved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "config": self._config_snapshot(),
            "running_config": self._running_config_text(),
        }
        try:
            self.config_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        except OSError as exc:
            print(f"% Unable to save startup configuration: {exc}")
            return False
        self.startup_config_text = payload["running_config"]
        return True

    def _build_command_trees(self) -> Tuple[CommandNode, CommandNode, CommandNode, CommandNode]:
        user_root = CommandNode("root")
        enabled_root = CommandNode("root")
        config_root = CommandNode("root")
        interface_root = CommandNode("root")

        self._add_command(user_root, ["enable"], "Turn on privileged commands", self._cmd_enable)
        self._add_command(user_root, ["exit"], "Exit from the EXEC", self._cmd_exit)
        self._add_command(user_root, ["quit"], "Exit from the EXEC", self._cmd_exit)

        self._add_command(enabled_root, ["disable"], "Turn off privileged commands", self._cmd_disable)
        self._add_command(enabled_root, ["configure", "terminal"], "Configure from the terminal", self._cmd_configure_terminal)
        self._add_command(enabled_root, ["write", "memory"], "Write the running configuration to memory", self._cmd_write_memory)
        self._add_command(enabled_root, ["terminal", "length"], "Set terminal line parameters", self._cmd_terminal_length)
        self._add_command(enabled_root, ["exit"], "Exit from the EXEC", self._cmd_exit)
        self._add_command(enabled_root, ["quit"], "Exit from the EXEC", self._cmd_exit)

        self._add_command(config_root, ["end"], "Exit from configure mode", self._cmd_end)
        self._add_command(config_root, ["exit"], "Exit from configure mode", self._cmd_exit)
        self._add_command(config_root, ["write", "memory"], "Write the running configuration to memory", self._cmd_write_memory)
        self._set_help(config_root, ["hostname"], "Set system's network name")
        self._set_help(config_root, ["interface"], "Select an interface to configure")
        self._set_help(config_root, ["route"], "Add a static route")
        self._set_help(config_root, ["no"], "Negate a command or set its defaults")

        self._add_command(interface_root, ["end"], "Exit from configure mode", self._cmd_end)
        self._add_command(interface_root, ["exit"], "Exit from interface configuration", self._cmd_exit)
        self._set_help(interface_root, ["description"], "Set interface description")
        self._set_help(interface_root, ["nameif"], "Set interface logical name")
        self._set_help(interface_root, ["security-level"], "Set interface security level")
        self._set_help(interface_root, ["ip"], "Interface Internet Protocol config commands")
        self._set_help(interface_root, ["ip", "address"], "Set the IP address and subnet mask")
        self._set_help(interface_root, ["shutdown"], "Shutdown the selected interface")
        self._set_help(interface_root, ["no"], "Negate a command or set its defaults")

        for root in (user_root, enabled_root, config_root, interface_root):
            self._set_help(root, ["ping"], "Send ICMP echo requests")
            self._set_help(root, ["traceroute"], "Trace the route to a destination")
            self._set_help(root, ["trace"], "Trace route commands")
            self._set_help(root, ["trace", "route"], "Trace the route to a destination")
            self._set_help(root, ["port"], "TCP port testing commands")
            self._set_help(root, ["port", "tester"], "Test a TCP port with the Windows FTP client")
            self._add_command(root, ["show", "cpu"], "Display processor utilization", self._show_cpu)
            self._add_command(root, ["show", "cpu", "detail"], "Display detailed processor utilization", self._show_cpu_detail)
            self._add_command(root, ["show", "memory"], "Display memory utilization", self._show_memory)
            self._add_command(root, ["show", "mem"], "Display memory utilization", self._show_memory)
            self._add_command(root, ["show", "memory", "detail"], "Display detailed memory utilization", self._show_memory_detail)
            self._add_command(root, ["show", "mem", "detail"], "Display detailed memory utilization", self._show_memory_detail)
            self._add_command(root, ["show", "tech"], "Display technical support information", self._show_tech)
            self._add_command(root, ["show", "tech-support"], "Display technical support information", self._show_tech)
            self._add_command(root, ["show", "tech", "sanitized"], "Display sanitized technical support information", self._show_tech_sanitized)
            self._add_command(root, ["show", "tech-support", "sanitized"], "Display sanitized technical support information", self._show_tech_sanitized)
            self._add_command(root, ["show", "version"], "System software information", self._show_version)
            self._add_command(root, ["show", "arp"], "Display the ARP table", self._show_arp)
            self._add_command(root, ["show", "processes"], "Display running processes", self._show_processes)
            self._set_help(root, ["show", "processes", "cpu-usage"], "Display sampled CPU utilization by process")
            self._set_help(root, ["show", "processes", "cpu-hog"], "Display processes using the most sampled CPU")
            self._set_help(root, ["show", "processes", "memory"], "Display process memory allocation")
            self._set_help(root, ["show", "processes", "internals"], "Display Windows process details")
            self._add_command(root, ["show", "conn"], "Display active TCP and UDP connections", self._show_connections)
            self._add_command(root, ["show", "conn", "count"], "Display active connection counts", self._show_conn_count)
            self._set_help(root, ["show", "conn", "all"], "Display all discovered connections")
            self._set_help(root, ["show", "conn", "detail"], "Include Windows connection details")
            self._set_help(root, ["show", "conn", "long"], "Display expanded endpoint information")
            self._set_help(root, ["show", "conn", "state"], "Filter by connection state")
            self._set_help(root, ["show", "conn", "protocol"], "Filter by TCP or UDP")
            self._set_help(root, ["show", "conn", "address"], "Filter by an endpoint address or address range")
            self._set_help(root, ["show", "conn", "port"], "Filter by an endpoint port or port range")
            self._add_command(root, ["show", "dns"], "Display Windows DNS resolver configuration", self._show_dns)
            self._set_help(root, ["show", "dns", "trusted-source"], "Display configured DNS servers")
            self._set_help(root, ["show", "dns", "trusted-source", "detail"], "Include Windows adapter names")
            self._add_command(root, ["show", "running-config"], "Current operating configuration", self._show_running_config)
            self._add_command(root, ["show", "running-config", "interface"], "Interface configuration", self._show_running_interfaces)
            self._add_command(root, ["show", "running-config", "route"], "Static route configuration", self._show_running_routes)
            self._add_command(root, ["show", "startup-config"], "Contents of the startup configuration", self._show_startup_config)
            self._add_command(root, ["show", "inventory"], "Hardware and platform inventory", self._show_inventory)
            self._add_command(root, ["show", "hostname"], "Display the device hostname", self._show_hostname)
            self._add_command(root, ["show", "system"], "Display host system information", self._show_system)
            self._add_command(root, ["show", "interface", "ip", "brief"], "Interface IP status and configuration", self._show_interface_ip_brief)
            self._add_command(root, ["show", "interface"], "Display interface details", self._show_interfaces_detail)
            self._add_command(root, ["show", "ip", "interface", "brief"], "Interface IP status and configuration", self._show_interface_ip_brief)
            self._add_command(root, ["show", "route"], "Display the route table", self._show_route)
            self._set_help(root, ["show"], "Show running system information")
            self._set_help(root, ["show", "interface"], "Interface information")
            self._set_help(root, ["show", "ip"], "IP information")
            self._set_help(root, ["show", "interface", "ip"], "IP interface information")
            self._set_help(root, ["show", "ip", "interface"], "Interface information")

        self._set_help(enabled_root, ["configure"], "Configuration commands")
        self._set_help(enabled_root, ["write"], "Write running configuration to memory, network, or terminal")
        self._set_help(enabled_root, ["terminal"], "Set terminal line parameters")
        self._set_help(config_root, ["write"], "Write running configuration to memory, network, or terminal")

        return user_root, enabled_root, config_root, interface_root

    @staticmethod
    def _add_command(root: CommandNode, words: List[str], help_text: str, action: Callable[[], Optional[bool]]) -> None:
        node = root
        for word in words:
            if word not in node.children:
                node.children[word] = CommandNode(help_text="")
            node = node.children[word]
        node.help_text = help_text
        node.action = action

    @staticmethod
    def _set_help(root: CommandNode, words: List[str], help_text: str) -> None:
        node = root
        for word in words:
            if word not in node.children:
                node.children[word] = CommandNode(help_text="")
            node = node.children[word]
        if not node.help_text:
            node.help_text = help_text

    def _current_tree(self) -> CommandNode:
        if self.config_submode == "config-if":
            return self.interface_tree
        if self.config_submode == "config":
            return self.config_tree
        if self.enabled:
            return self.enabled_tree
        return self.user_tree

    def cmdloop(self) -> None:
        print("Cisco Adaptive Security Appliance Software Emulator")
        print("Type ? for help.")
        while True:
            try:
                line = self._read_line()
            except EOFError:
                print()
                break
            should_exit = self._dispatch_line(line)
            if should_exit:
                break

    def _read_line(self) -> str:
        if not sys.stdin.isatty() or msvcrt is None:
            return input(self.prompt)

        buffer = ""
        cursor = 0
        history_index = len(self.history)
        print(self.prompt, end="", flush=True)
        self._last_input_width = len(self.prompt)
        while True:
            char = msvcrt.getwch()
            if char in ("\r", "\n"):
                print()
                if buffer.strip() and (not self.history or self.history[-1] != buffer):
                    self.history.append(buffer)
                return buffer
            if char == "\t":
                buffer, cursor = self._handle_tab(buffer, cursor)
                continue
            if char in ("\b", "\x7f"):
                if cursor > 0:
                    buffer = buffer[: cursor - 1] + buffer[cursor:]
                    cursor -= 1
                    self._redraw_input(buffer, cursor)
                continue
            if char == "\x03":
                raise KeyboardInterrupt
            if char in ("\x00", "\xe0"):
                key = msvcrt.getwch()
                if key == "H" and self.history:
                    history_index = max(0, history_index - 1)
                    buffer = self.history[history_index]
                    cursor = len(buffer)
                    self._redraw_input(buffer, cursor)
                elif key == "P" and self.history:
                    history_index = min(len(self.history), history_index + 1)
                    buffer = "" if history_index == len(self.history) else self.history[history_index]
                    cursor = len(buffer)
                    self._redraw_input(buffer, cursor)
                elif key == "K" and cursor > 0:
                    cursor -= 1
                    print("\b", end="", flush=True)
                elif key == "M" and cursor < len(buffer):
                    print(buffer[cursor], end="", flush=True)
                    cursor += 1
                elif key == "S" and cursor < len(buffer):
                    buffer = buffer[:cursor] + buffer[cursor + 1:]
                    self._redraw_input(buffer, cursor)
                elif key == "G":
                    while cursor > 0:
                        print("\b", end="", flush=True)
                        cursor -= 1
                elif key == "O":
                    while cursor < len(buffer):
                        print(buffer[cursor], end="", flush=True)
                        cursor += 1
                continue
            if char.isprintable():
                buffer = buffer[:cursor] + char + buffer[cursor:]
                cursor += len(char)
                self._redraw_input(buffer, cursor)

    def _redraw_input(self, buffer: str, cursor: int) -> None:
        line = self.prompt + buffer
        clear_width = max(self._last_input_width, len(line)) + 4
        print("\r" + " " * clear_width + "\r" + line, end="", flush=True)
        self._last_input_width = len(line)
        backtrack = len(buffer) - cursor
        if backtrack:
            print("\b" * backtrack, end="", flush=True)

    def _handle_tab(self, buffer: str, cursor: int) -> Tuple[str, int]:
        prefix = buffer[:cursor]
        suffix = buffer[cursor:]
        completed, suggestions = self._complete_line(prefix)
        if completed != prefix:
            new_buffer = completed + suffix
            new_cursor = len(completed)
            if suffix:
                self._redraw_input(new_buffer, new_cursor)
            else:
                addition = completed[len(prefix):]
                print(addition, end="", flush=True)
            return new_buffer, new_cursor
        if suggestions:
            print()
            self._print_columns(suggestions)
            print(self.prompt + buffer, end="", flush=True)
            backtrack = len(buffer) - cursor
            if backtrack:
                print("\b" * backtrack, end="", flush=True)
        return buffer, cursor

    def _complete_line(self, buffer: str) -> Tuple[str, List[str]]:
        words, trailing_space = split_words(buffer)
        node = self._current_tree()

        if not words:
            suggestions = sorted(node.children)
            return buffer, suggestions

        dynamic = self._dynamic_completion(buffer, words, trailing_space)
        if dynamic is not None:
            return dynamic

        path_words = words[:-1] if not trailing_space else words
        current = words[-1] if words and not trailing_space else ""

        for word in path_words:
            resolved = self._resolve_token(word, node.children)
            if resolved[0] != "ok":
                return buffer, []
            node = node.children[resolved[1]]

        options = sorted(name for name in node.children if name.startswith(current.lower()))
        if not options:
            return buffer, []
        if len(options) == 1:
            completed_word = options[0]
            new_words = path_words + [completed_word]
            completed = " ".join(new_words)
            if node.children[completed_word].children:
                completed += " "
            return completed, [completed_word]
        common = os.path.commonprefix(options)
        if len(common) > len(current):
            return " ".join(path_words + [common]), options
        return buffer, options

    def _dispatch_line(self, line: str) -> bool:
        line = line.rstrip()
        if not line:
            return False

        redirected = self._handle_show_redirection(line)
        if redirected is not None:
            return redirected

        if line.strip() == "?":
            self._print_help_for_prefix("")
            return False

        if "?" in line:
            self._handle_question_mark(line)
            return False

        if self._handle_diagnostic_command(line):
            return False

        if self._handle_show_variants(line):
            return False

        handled, should_exit = self._handle_mode_specific_command(line)
        if handled:
            return should_exit

        status, node, error_index = self._resolve_command(line)
        if status == "ok" and node and node.action:
            result = node.action()
            return bool(result)
        if status == "incomplete":
            print("% Incomplete command.")
            return False
        self._print_invalid_marker(line, error_index)
        return False

    def _handle_show_redirection(self, line: str) -> Optional[bool]:
        """Save read-only show output without exposing arbitrary shell redirection."""
        if ">" not in line:
            return None

        command, separator, target = line.partition(">")
        command = command.strip()
        target = target.strip()
        words = command.split()
        if not command or not separator or not target or ">" in target:
            print("% Invalid output redirection.")
            return False
        if not words or words[0].lower() != "show":
            print("% Output redirection is supported only for show commands.")
            return False

        destination = Path(target)
        if destination.is_absolute() or len(destination.parts) != 1 or destination.name in {"", ".", ".."}:
            print("% Output file must be a filename in the current directory.")
            return False

        output = io.StringIO()
        with redirect_stdout(output):
            should_exit = self._dispatch_line(command)
        try:
            destination.write_text(output.getvalue(), encoding="utf-8")
        except OSError as exc:
            print(f"% Unable to write {destination.name}: {exc}")
            return False
        print(f"Output written to {destination.name}")
        return should_exit

    def _handle_show_variants(self, line: str) -> bool:
        words = line.split()
        if len(words) < 2 or not self._matches(words[0], "show"):
            return False

        show_node = self._current_tree().children.get("show")
        if show_node is None:
            return False
        status, subject = self._resolve_token(words[1], show_node.children)
        if status != "ok" or subject is None:
            return False

        if subject == "interface":
            if len(words) == 2:
                self._show_interfaces_detail()
                return True
            if len(words) == 3 and not self._matches(words[2], "ip"):
                interface_key = self._resolve_interface_name(words[2])
                if interface_key is None:
                    self._print_invalid_marker(line, line.lower().find(words[2].lower()))
                else:
                    self._show_interface_detail(self.interfaces[interface_key])
                return True
            return False

        if subject == "running-config":
            if len(words) == 4 and self._matches(words[2], "interface"):
                interface_key = self._resolve_interface_name(words[3])
                if interface_key is None:
                    self._print_invalid_marker(line, line.lower().find(words[3].lower()))
                else:
                    self._show_running_interface_block(self.interfaces[interface_key])
                return True
            return False

        if subject == "cpu":
            if len(words) == 2:
                self._show_cpu()
            elif len(words) == 3 and self._matches(words[2], "detail"):
                self._show_cpu_detail()
            elif len(words) == 4 and self._matches(words[2], "detail"):
                limit = self._parse_process_limit(words[3])
                if limit is not None:
                    self._show_cpu_detail(limit)
            else:
                self._print_invalid_marker(line, line.lower().find(words[2].lower()))
            return True

        if subject in {"memory", "mem"}:
            if len(words) == 2:
                self._show_memory()
            elif len(words) == 3 and self._matches(words[2], "detail"):
                self._show_memory_detail()
            elif len(words) == 4 and self._matches(words[2], "detail"):
                limit = self._parse_process_limit(words[3])
                if limit is not None:
                    self._show_memory_detail(limit)
            else:
                self._print_invalid_marker(line, line.lower().find(words[2].lower()))
            return True

        if subject == "processes":
            self._handle_show_processes_variant(line, words)
            return True

        if subject == "conn":
            self._handle_show_conn_variant(line, words)
            return True

        if subject == "dns":
            if len(words) == 2:
                self._show_dns(detail=False)
            elif len(words) == 3 and self._matches(words[2], "trusted-source"):
                self._show_dns(detail=False)
            elif len(words) == 4 and self._matches(words[2], "trusted-source") and self._matches(words[3], "detail"):
                self._show_dns(detail=True)
            else:
                self._print_invalid_marker(line, line.lower().find(words[-1].lower()))
            return True

        return False

    def _handle_show_processes_variant(self, line: str, words: List[str]) -> None:
        if len(words) == 2:
            self._show_processes()
            return

        if self._matches(words[2], "cpu-usage"):
            non_zero = False
            sorted_output = False
            for option in words[3:]:
                if self._matches(option, "non-zero") and not non_zero:
                    non_zero = True
                elif self._matches(option, "sorted") and not sorted_output:
                    sorted_output = True
                else:
                    self._print_invalid_marker(line, line.lower().find(option.lower()))
                    return
            self._show_processes_cpu_usage(non_zero=non_zero, sorted_output=sorted_output)
            return

        if len(words) == 3 and self._matches(words[2], "memory"):
            self._show_processes_memory()
            return
        if len(words) == 3 and self._matches(words[2], "cpu-hog"):
            self._show_processes_cpu_hog()
            return
        if len(words) == 3 and self._matches(words[2], "internals"):
            self._show_processes_internals()
            return
        self._print_invalid_marker(line, line.lower().find(words[2].lower()))

    def _handle_show_conn_variant(self, line: str, words: List[str]) -> None:
        if len(words) == 2:
            self._show_connections()
            return
        if len(words) == 3 and self._matches(words[2], "count"):
            self._show_conn_count()
            return

        filters = ConnectionFilters()
        index = 2
        while index < len(words):
            token = words[index]
            if self._matches(token, "all"):
                filters.show_all = True
                index += 1
            elif self._matches(token, "detail"):
                filters.detail = True
                index += 1
            elif self._matches(token, "long"):
                filters.long_format = True
                index += 1
            elif self._matches(token, "protocol"):
                if index + 1 >= len(words):
                    print("% Incomplete command.")
                    return
                protocol = words[index + 1].lower()
                if protocol not in {"tcp", "udp"}:
                    self._print_invalid_marker(line, line.lower().find(words[index + 1].lower()))
                    return
                filters.protocols.append(protocol.upper())
                index += 2
            elif self._matches(token, "state"):
                if index + 1 >= len(words):
                    print("% Incomplete command.")
                    return
                states = [state.strip().lower() for state in words[index + 1].split(",") if state.strip()]
                if not states:
                    self._print_invalid_marker(line, line.lower().find(words[index + 1].lower()))
                    return
                filters.states.extend(states)
                index += 2
            elif self._matches(token, "address"):
                if index + 1 >= len(words) or not self._valid_connection_address(words[index + 1]):
                    error_index = line.lower().find(words[index].lower()) if index + 1 >= len(words) else line.lower().find(words[index + 1].lower())
                    self._print_invalid_marker(line, error_index)
                    return
                address = words[index + 1]
                mask: Optional[str] = None
                index += 2
                if index < len(words) and self._matches(words[index], "netmask"):
                    if index + 1 >= len(words) or not self._valid_connection_netmask(address, words[index + 1]):
                        error_index = line.lower().find(words[index].lower()) if index + 1 >= len(words) else line.lower().find(words[index + 1].lower())
                        self._print_invalid_marker(line, error_index)
                        return
                    mask = words[index + 1]
                    index += 2
                filters.address_filters.append((address, mask))
            elif self._matches(token, "port"):
                if index + 1 >= len(words) or not self._valid_connection_port(words[index + 1]):
                    error_index = line.lower().find(words[index].lower()) if index + 1 >= len(words) else line.lower().find(words[index + 1].lower())
                    self._print_invalid_marker(line, error_index)
                    return
                filters.port_filters.append(words[index + 1])
                index += 2
            else:
                self._print_invalid_marker(line, line.lower().find(token.lower()))
                return
        self._show_connections(filters)

    @staticmethod
    def _valid_connection_address(value: str) -> bool:
        values = value.split("-", 1)
        try:
            addresses = [ipaddress.ip_address(item) for item in values]
        except ValueError:
            return False
        return len(addresses) in {1, 2} and (len(addresses) == 1 or addresses[0].version == addresses[1].version)

    @staticmethod
    def _valid_connection_netmask(address: str, mask: str) -> bool:
        if "-" in address:
            return False
        try:
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def _valid_connection_port(value: str) -> bool:
        try:
            values = value.split("-", 1)
            start, end = int(values[0]), int(values[-1])
        except ValueError:
            return False
        return 0 <= start <= end <= 65535

    def _handle_diagnostic_command(self, line: str) -> bool:
        """Run bounded Windows diagnostics through ASA-style EXEC commands."""
        words = line.split()
        if not words:
            return False

        if self._matches(words[0], "ping"):
            self._run_ping(words[1:])
            return True

        if words[0].lower() == "port":
            if len(words) == 1:
                print("% Incomplete command.")
                return True
            if self._matches(words[1], "tester"):
                self._run_port_tester(words[2:])
                return True
            return False

        # Check the two-word alias before traceroute: "trace" is a valid
        # abbreviation of "traceroute" and would otherwise capture it.
        if words[0].lower() == "trace" and len(words) >= 2 and self._matches(words[1], "route"):
            self._run_traceroute(words[2:])
            return True

        if words[0].lower() == "trace" and len(words) == 1:
            print("% Incomplete command.")
            return True

        if self._matches(words[0], "traceroute"):
            self._run_traceroute(words[1:])
            return True
        return False

    @staticmethod
    def _valid_diagnostic_host(host: str) -> bool:
        """Allow IPv4 addresses and ordinary host names without accepting flags."""
        if len(host) > 253:
            return False
        try:
            ipaddress.IPv4Address(host)
            return True
        except ValueError:
            return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host))

    def _parse_diagnostic_arguments(self, arguments: List[str], default_limit: int, maximum_limit: int) -> Optional[Tuple[str, int]]:
        if not arguments:
            print("% Incomplete command.")
            return None
        if len(arguments) > 2:
            print("% Invalid input detected at '^' marker.")
            return None

        host = arguments[0]
        if not self._valid_diagnostic_host(host):
            print("% Invalid destination.")
            return None

        limit = default_limit
        if len(arguments) == 2:
            try:
                limit = int(arguments[1])
            except ValueError:
                print(f"% Expected a number between 1 and {maximum_limit}.")
                return None
            if not 1 <= limit <= maximum_limit:
                print(f"% Expected a number between 1 and {maximum_limit}.")
                return None
        return host, limit

    def _run_ping(self, arguments: List[str]) -> None:
        parsed = self._parse_diagnostic_arguments(arguments, default_limit=4, maximum_limit=20)
        if parsed is None:
            return
        host, repeat = parsed
        output = run_command(["ping", "-n", str(repeat), host])
        if output:
            print(output)

    def _run_traceroute(self, arguments: List[str]) -> None:
        parsed = self._parse_diagnostic_arguments(arguments, default_limit=10, maximum_limit=30)
        if parsed is None:
            return
        host, hops = parsed
        output = run_command(["tracert", "-d", "-h", str(hops), "-w", "1000", host])
        if output:
            print(output)

    def _run_port_tester(self, arguments: List[str]) -> None:
        if len(arguments) < 2:
            print("% Incomplete command.")
            return
        if len(arguments) > 2:
            print("% Invalid input detected at '^' marker.")
            return

        host, port_text = arguments
        if not self._valid_diagnostic_host(host):
            print("% Invalid destination.")
            return
        try:
            port = int(port_text)
        except ValueError:
            print("% Port must be a whole number between 1 and 65535.")
            return
        if not 1 <= port <= 65535:
            print("% Port must be a whole number between 1 and 65535.")
            return

        output = run_ftp_port_test(host, port)
        if output:
            print(output)
        # Non-FTP services commonly close the control socket immediately after
        # accepting it, which Windows FTP reports as a remote-host close.
        if re.search(r"connected to\s+|connection closed by remote host", output, flags=re.IGNORECASE):
            print(f"Port {port} on {host} is reachable.")
        elif not output.lower().startswith("unable to run ftp"):
            print(f"Port {port} on {host} is not reachable.")

    @staticmethod
    def _parse_process_limit(value: str) -> Optional[int]:
        try:
            limit = int(value)
        except ValueError:
            print("% Process count must be a whole number between 1 and 100.")
            return None
        if not 1 <= limit <= 100:
            print("% Process count must be between 1 and 100.")
            return None
        return limit

    def _resolve_command(self, line: str) -> Tuple[str, Optional[CommandNode], int]:
        words = line.split()
        node = self._current_tree()
        cursor = 0

        for word in words:
            token_index = line.find(word, cursor)
            cursor = token_index + len(word)
            status, resolved = self._resolve_token(word, node.children)
            if status == "missing":
                return "invalid", None, token_index
            if status == "ambiguous":
                print("% Ambiguous command.")
                return "invalid", None, token_index
            node = node.children[resolved]

        if node.action is None:
            return "incomplete", node, len(line)
        return "ok", node, len(line)

    @staticmethod
    def _resolve_token(token: str, options: Dict[str, CommandNode]) -> Tuple[str, Optional[str]]:
        matches = sorted(name for name in options if name.startswith(token.lower()))
        if not matches:
            return "missing", None
        if len(matches) > 1 and token.lower() not in options:
            return "ambiguous", None
        exact = token.lower() if token.lower() in options else matches[0]
        return "ok", exact

    def _handle_question_mark(self, line: str) -> None:
        prefix = line[: line.index("?")]
        self._print_help_for_prefix(prefix)

    def _print_help_for_prefix(self, prefix: str) -> None:
        words, trailing_space = split_words(prefix)
        node = self._current_tree()

        if self._print_dynamic_help(words, trailing_space):
            return

        if not words:
            self._print_help_entries(node.children)
            return

        path_words = words if trailing_space else words[:-1]
        partial = "" if trailing_space else words[-1].lower()

        for word in path_words:
            status, resolved = self._resolve_token(word, node.children)
            if status != "ok":
                print("% Invalid input detected.")
                return
            node = node.children[resolved]

        matches = {
            name: child
            for name, child in node.children.items()
            if name.startswith(partial)
        }
        if not matches:
            print("% Unrecognized command")
            return
        self._print_help_entries(matches)

    @staticmethod
    def _print_help_entries(entries: Dict[str, CommandNode]) -> None:
        width = max((len(name) for name in entries), default=0) + 2
        for name in sorted(entries):
            print(f"  {name.ljust(width)}{entries[name].help_text}")

    @staticmethod
    def _print_columns(items: List[str]) -> None:
        for item in items:
            print(item)

    @staticmethod
    def _print_invalid_marker(line: str, index: int) -> None:
        pointer = " " * max(index, 0) + "^"
        print("% Invalid input detected at '^' marker.")
        print(line)
        print(pointer)

    def _cmd_enable(self) -> None:
        self.enabled = True

    def _cmd_disable(self) -> None:
        self.enabled = False
        self.config_submode = "exec"
        self.current_interface = None

    def _cmd_end(self) -> None:
        self.config_submode = "exec"
        self.current_interface = None

    def _cmd_exit(self) -> bool:
        if self.config_submode == "config-if":
            self.config_submode = "config"
            self.current_interface = None
            return False
        if self.config_submode == "config":
            self.config_submode = "exec"
            return False
        print("Logoff")
        return True

    def _cmd_configure_terminal(self) -> None:
        if not self.enabled:
            print("% Privileged mode required.")
            return
        self.config_submode = "config"

    def _cmd_write_memory(self) -> None:
        print("Building configuration...")
        if self._save_config():
            print("[OK]")

    def _cmd_terminal_length(self) -> None:
        print("% Incomplete command.")

    def _apply_interface_admin_state(self, interface: EmulatedInterface, enabled: bool) -> bool:
        action = "enabled" if enabled else "disabled"
        if not self._ensure_admin():
            return False
        ok, output = run_live_command(
            [
                "netsh",
                "interface",
                "set",
                "interface",
                f"name={interface.windows_name}",
                f"admin={action}",
            ]
        )
        if not ok:
            self._print_windows_error(output)
        else:
            self._refresh_live_state()
        return ok

    def _apply_static_ip(self, interface: EmulatedInterface, ip_address: str, mask: str) -> bool:
        if not self._ensure_admin():
            return False
        ok, output = run_live_command(
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "address",
                f"name={interface.windows_name}",
                "static",
                ip_address,
                mask,
                "none",
            ]
        )
        if not ok:
            self._print_windows_error(output)
        else:
            self._refresh_live_state()
        return ok

    def _apply_dhcp_ip(self, interface: EmulatedInterface) -> bool:
        if not self._ensure_admin():
            return False
        ok, output = run_live_command(
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "address",
                f"name={interface.windows_name}",
                "dhcp",
            ]
        )
        if not ok:
            self._print_windows_error(output)
        else:
            self._refresh_live_state()
        return ok

    def _apply_route(self, interface: EmulatedInterface, route: StaticRoute, negate: bool) -> bool:
        prefix_length = mask_to_prefix(route.mask)
        if prefix_length is None:
            print("% Invalid route netmask.")
            return False
        if not self._ensure_admin():
            return False

        action = "delete" if negate else "add"
        command = [
            "netsh",
            "interface",
            "ipv4",
            action,
            "route",
            f"prefix={route.destination}/{prefix_length}",
            f"interface={interface.windows_name}",
            f"nexthop={route.gateway}",
            "store=persistent",
        ]
        if not negate:
            command.insert(-1, f"metric={route.metric}")

        ok, output = run_live_command(command)
        if not ok:
            self._print_windows_error(output)
        else:
            self._refresh_live_state()
        return ok

    def _refresh_live_state(self) -> None:
        discovered = parse_ipconfig()
        if not discovered:
            return

        existing_by_windows_name = {
            interface.windows_name.lower(): interface
            for interface in self.interfaces.values()
        }
        refreshed: Dict[str, EmulatedInterface] = {}
        for index, discovered_interface in enumerate(discovered, start=1):
            existing = existing_by_windows_name.get(discovered_interface.name.lower())
            if existing is None:
                asa_name = self._asa_interface_name(index, discovered_interface.name)
                existing = EmulatedInterface(
                    asa_name=asa_name,
                    windows_name=discovered_interface.name,
                    mac_address=discovered_interface.mac_address,
                    live_ipv4=None,
                    live_method="manual",
                    description=f"Windows adapter: {discovered_interface.name}",
                )

            existing.mac_address = discovered_interface.mac_address
            existing.live_ipv4 = discovered_interface.ipv4_addresses[0] if discovered_interface.ipv4_addresses else None
            existing.live_method = "DHCP" if (discovered_interface.dhcp_enabled or "").lower() == "yes" else "manual"
            if existing.dhcp_enabled:
                existing.configured_ip = None
                existing.configured_mask = None
            refreshed[existing.asa_name.lower()] = existing

        self.base_interfaces = discovered
        self.interfaces = refreshed

    @staticmethod
    def _ensure_admin() -> bool:
        if is_admin():
            return True
        print("% Windows administrator privileges are required to apply this command.")
        print("% Restart PowerShell as Administrator and run the emulator again.")
        return False

    @staticmethod
    def _print_windows_error(output: str) -> None:
        print("% Windows rejected the live network change.")
        if output:
            print(output)

    def _dynamic_completion(self, buffer: str, words: List[str], trailing_space: bool) -> Optional[Tuple[str, List[str]]]:
        show_completion = self._complete_show_variant(buffer, words, trailing_space)
        if show_completion is not None:
            return show_completion

        if self.config_submode == "config":
            if words and self._matches(words[0], "interface"):
                return self._complete_value_command(buffer, words, trailing_space, self._interface_completion_names())
            if words and self._matches(words[0], "route"):
                return self._complete_value_command(buffer, words, trailing_space, self._interface_completion_names())
            if words and self._matches(words[0], "no") and len(words) > 1 and self._matches(words[1], "route"):
                return self._complete_value_command(buffer, words, trailing_space, self._interface_completion_names(), offset=1)
        if self.config_submode == "config-if":
            if words and self._matches(words[0], "ip"):
                if len(words) == 3 and not trailing_space and self._matches(words[1], "address"):
                    return self._complete_last_word(words, ["dhcp"], append_space=True)
                if len(words) == 4 and not trailing_space and self._matches(words[1], "address") and self._matches(words[2], "dhcp"):
                    return self._complete_last_word(words, ["setroute"], append_space=True)
                if len(words) <= 2:
                    options = ["address"]
                elif len(words) == 3 and self._matches(words[1], "address"):
                    options = ["dhcp"]
                elif len(words) == 4 and self._matches(words[1], "address") and self._matches(words[2], "dhcp"):
                    options = ["setroute"]
                else:
                    options = []
                return self._complete_value_command(buffer, words, trailing_space, options)
            if words and self._matches(words[0], "no"):
                options = ["description", "ip", "nameif", "security-level", "shutdown"]
                return self._complete_value_command(buffer, words, trailing_space, options)
        return None

    def _complete_show_variant(self, buffer: str, words: List[str], trailing_space: bool) -> Optional[Tuple[str, List[str]]]:
        if len(words) < 2 or not self._matches(words[0], "show"):
            return None
        show_node = self._current_tree().children.get("show")
        if show_node is None:
            return None
        status, subject = self._resolve_token(words[1], show_node.children)
        if status != "ok" or subject is None:
            return None

        if subject == "interface":
            options = ["ip", *self._interface_completion_names()]
            if len(words) == 2 and trailing_space:
                return buffer, sorted(options)
            if len(words) == 3 and not trailing_space:
                return self._complete_last_word(words, options, append_space=True)
            return None

        if subject == "running-config":
            if len(words) == 3 and self._matches(words[2], "interface") and trailing_space:
                return buffer, self._interface_completion_names()
            if len(words) == 4 and self._matches(words[2], "interface") and not trailing_space:
                return self._complete_last_word(words, self._interface_completion_names(), append_space=False)
            return None

        if subject == "conn":
            if len(words) == 3 and trailing_space and self._matches(words[2], "protocol"):
                return buffer, ["tcp", "udp"]
            if len(words) == 3 and trailing_space and self._matches(words[2], "state"):
                return buffer, ["up", "tcp-embryonic", "established", "time-wait"]
            if len(words) == 4 and trailing_space and self._matches(words[2], "address"):
                return buffer, ["netmask", "port"]
            return None

        if subject == "processes":
            process_options = ["cpu-hog", "cpu-usage", "internals", "memory"]
            if len(words) == 2 and trailing_space:
                return buffer, process_options
            if len(words) == 3 and not trailing_space:
                return self._complete_last_word(words, process_options, append_space=True)
            if len(words) == 3 and trailing_space and self._matches(words[2], "cpu-usage"):
                return buffer, ["non-zero", "sorted"]
            if len(words) == 4 and not trailing_space and self._matches(words[2], "cpu-usage"):
                return self._complete_last_word(words, ["non-zero", "sorted"], append_space=True)
            if len(words) == 4 and trailing_space and self._matches(words[2], "cpu-usage"):
                remaining = [option for option in ["non-zero", "sorted"] if option not in words[3].lower()]
                return (buffer, remaining) if remaining else None
            return None

        if subject in {"cpu", "memory", "mem"}:
            if len(words) == 2 and trailing_space:
                return buffer, ["detail"]
            if len(words) == 3 and not trailing_space:
                return self._complete_last_word(words, ["detail"], append_space=True)
        return None

    def _interface_completion_names(self) -> List[str]:
        names = [interface.asa_name for interface in self.interfaces.values()]
        names.extend(interface.nameif for interface in self.interfaces.values() if interface.nameif)
        return sorted(set(names))

    @staticmethod
    def _complete_last_word(words: List[str], options: List[str], append_space: bool) -> Tuple[str, List[str]]:
        current = words[-1].lower()
        matches = sorted(option for option in options if option.lower().startswith(current))
        if len(matches) == 1:
            completed = " ".join(words[:-1] + [matches[0]])
            return (completed + " " if append_space else completed), matches
        common = os.path.commonprefix(matches)
        if len(common) > len(current):
            return " ".join(words[:-1] + [common]), matches
        return " ".join(words), matches

    def _complete_value_command(
        self,
        buffer: str,
        words: List[str],
        trailing_space: bool,
        options: List[str],
        offset: int = 0,
    ) -> Optional[Tuple[str, List[str]]]:
        base_index = 1 + offset
        if len(words) < base_index or not options:
            return None

        if len(words) == base_index and trailing_space:
            return buffer, sorted(options)
        if len(words) == base_index + 1 and not trailing_space:
            current = words[-1].lower()
            matches = sorted(option for option in options if option.lower().startswith(current))
            if not matches:
                return buffer, []
            if len(matches) == 1:
                completed = " ".join(words[:-1] + [matches[0]])
                return completed + " ", matches
            common = os.path.commonprefix(matches)
            if len(common) > len(current):
                return " ".join(words[:-1] + [common]), matches
            return buffer, matches
        return None

    def _print_dynamic_help(self, words: List[str], trailing_space: bool) -> bool:
        if words and self._matches(words[0], "ping"):
            if len(words) == 1 and trailing_space:
                print("  <hostname-or-ip>  Destination to probe")
                return True
            if len(words) == 2 and trailing_space:
                print("  <1-20>            Number of echo requests (default: 4)")
                return True

        trace_route = (
            words
            and words[0].lower() == "trace"
            and len(words) >= 2
            and self._matches(words[1], "route")
        )
        if (words and self._matches(words[0], "traceroute")) or trace_route:
            argument_index = 2 if trace_route else 1
            if len(words) == argument_index and trailing_space:
                print("  <hostname-or-ip>  Destination to trace")
                return True
            if len(words) == argument_index + 1 and trailing_space:
                print("  <1-30>            Maximum hops (default: 10)")
                return True

        if words and words[0].lower() == "port" and len(words) >= 2 and self._matches(words[1], "tester"):
            if len(words) == 2 and trailing_space:
                print("  <hostname-or-ip>  Destination to test")
                return True
            if len(words) == 3 and trailing_space:
                print("  <1-65535>         TCP port to test with Windows FTP")
                return True

        if len(words) >= 2 and self._matches(words[0], "show"):
            show_node = self._current_tree().children.get("show")
            if show_node is not None:
                status, subject = self._resolve_token(words[1], show_node.children)
                if status == "ok" and subject == "interface":
                    if len(words) == 2 and trailing_space:
                        print("  ip                    Interface IP information")
                        self._print_interface_name_help()
                        return True
                    if len(words) == 3 and not trailing_space:
                        matches = [
                            name for name in self._interface_completion_names()
                            if name.lower().startswith(words[2].lower())
                        ]
                        if matches:
                            for name in matches:
                                print(f"  {name}")
                            return True
                if status == "ok" and subject == "running-config":
                    if len(words) == 2 and trailing_space:
                        print("  interface  Interface configuration")
                        print("  route      Static route configuration")
                        return True
                    if len(words) == 3 and self._matches(words[2], "interface") and trailing_space:
                        self._print_interface_name_help()
                        return True
                if status == "ok" and subject == "conn":
                    if len(words) == 3 and self._matches(words[2], "protocol") and trailing_space:
                        print("  tcp  Display TCP connections")
                        print("  udp  Display UDP connections")
                        return True
                    if len(words) == 3 and self._matches(words[2], "state") and trailing_space:
                        print("  up             Display established TCP and active UDP connections")
                        print("  tcp-embryonic  Display TCP connections awaiting handshake completion")
                        print("  <state,...>    Filter by one or more comma-separated Windows connection states")
                        return True
                    if len(words) == 3 and self._matches(words[2], "address") and trailing_space:
                        print("  <ip[-ip]>  Match either endpoint by an IP address or address range")
                        return True
                    if len(words) == 3 and self._matches(words[2], "port") and trailing_space:
                        print("  <port[-port]>  Match either endpoint by a port or port range")
                        return True
                if status == "ok" and subject == "processes":
                    if len(words) == 2 and trailing_space:
                        print("  cpu-usage  Display sampled CPU utilization by process")
                        print("  cpu-hog    Display processes using the most sampled CPU")
                        print("  internals  Display Windows process details")
                        print("  memory     Display process memory allocation")
                        return True
                    if len(words) == 3 and self._matches(words[2], "cpu-usage") and trailing_space:
                        print("  non-zero  Include only processes with sampled CPU utilization")
                        print("  sorted    Sort processes by sampled CPU utilization")
                        return True
                if status == "ok" and subject in {"cpu", "memory", "mem"} and len(words) == 2 and trailing_space:
                    print("  detail  Include top Windows process utilization")
                    return True
                if status == "ok" and subject in {"cpu", "memory", "mem"} and len(words) == 3 and self._matches(words[2], "detail") and trailing_space:
                    print("  <1-100>  Number of top processes to display")
                    return True

        if self.config_submode == "config" and words:
            if self._matches(words[0], "interface"):
                self._print_interface_name_help()
                return True
            if self._matches(words[0], "route"):
                self._print_route_interface_help()
                return True
            if self._matches(words[0], "no") and len(words) > 1 and self._matches(words[1], "route"):
                self._print_route_interface_help()
                return True

        if self.config_submode == "config-if" and words:
            first = words[0]
            if self._matches(first, "ip"):
                if len(words) == 1 or (len(words) == 2 and not trailing_space):
                    print("  address  Set the IP address and subnet mask")
                    return True
                if len(words) >= 2 and self._matches(words[1], "address"):
                    print("  A.B.C.D  Interface IP address")
                    print("  dhcp     Use DHCP to obtain interface IP address")
                    return True
            if self._matches(first, "no"):
                print("  description     Reset interface description")
                print("  ip              Remove interface IP settings")
                print("  nameif          Remove logical interface name")
                print("  security-level  Remove interface security level")
                print("  shutdown        Bring the interface up")
                return True
        return False

    def _print_interface_name_help(self) -> None:
        width = max((len(interface.asa_name) for interface in self.interfaces.values()), default=0) + 2
        for interface in self.interfaces.values():
            print(f"  {interface.asa_name.ljust(width)}{interface.windows_name}")

    def _print_route_interface_help(self) -> None:
        width = max((len(interface.asa_name) for interface in self.interfaces.values()), default=0) + 2
        for interface in self.interfaces.values():
            label = interface.nameif or interface.windows_name
            print(f"  {interface.asa_name.ljust(width)}Route out via {label}")

    @staticmethod
    def _matches(value: str, keyword: str) -> bool:
        return keyword.startswith(value.lower())

    def _handle_mode_specific_command(self, line: str) -> Tuple[bool, bool]:
        if self.config_submode == "config":
            return self._handle_global_config_command(line)
        if self.config_submode == "config-if":
            return self._handle_interface_config_command(line)
        if self.enabled and line.lower().startswith("terminal length "):
            print(f"Terminal length set to {line.split()[-1]}")
            return True, False
        return False, False

    def _handle_global_config_command(self, line: str) -> Tuple[bool, bool]:
        words = line.split()
        lowered = [word.lower() for word in words]
        if not words:
            return True, False

        if self._matches(lowered[0], "hostname"):
            if len(words) < 2:
                print("% Incomplete command.")
            else:
                self.hostname = self._sanitize_hostname(words[1])
            return True, False

        if self._matches(lowered[0], "interface"):
            if len(words) < 2:
                print("% Incomplete command.")
                return True, False
            resolved = self._resolve_interface_name(words[1])
            if resolved is None:
                self._print_invalid_marker(line, line.lower().find(words[1].lower()))
                return True, False
            self.current_interface = resolved
            self.config_submode = "config-if"
            return True, False

        if self._matches(lowered[0], "route"):
            self._configure_route(words, negate=False)
            return True, False

        if self._matches(lowered[0], "no") and len(words) > 1 and self._matches(lowered[1], "route"):
            self._configure_route(words[1:], negate=True)
            return True, False

        return False, False

    def _handle_interface_config_command(self, line: str) -> Tuple[bool, bool]:
        if not self.current_interface:
            return False, False

        interface = self.interfaces[self.current_interface]
        words = line.split()
        lowered = [word.lower() for word in words]
        if not words:
            return True, False

        if self._matches(lowered[0], "description"):
            if len(words) < 2:
                print("% Incomplete command.")
            else:
                interface.description = line.split(None, 1)[1]
            return True, False

        if self._matches(lowered[0], "nameif"):
            if len(words) < 2:
                print("% Incomplete command.")
            elif len(words) != 2 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,47}", words[1]):
                print("% Invalid interface name.")
            elif any(
                other is not interface and other.nameif and other.nameif.lower() == words[1].lower()
                for other in self.interfaces.values()
            ):
                print("% Interface name is already in use.")
            else:
                interface.nameif = words[1]
            return True, False

        if self._matches(lowered[0], "security-level"):
            if len(words) < 2:
                print("% Incomplete command.")
            elif len(words) != 2:
                self._print_invalid_marker(line, line.lower().find(words[2].lower()))
            else:
                try:
                    value = int(words[1])
                    if 0 <= value <= 100:
                        interface.security_level = value
                    else:
                        print("% Security level must be between 0 and 100.")
                except ValueError:
                    print("% Invalid security level.")
            return True, False

        if self._matches(lowered[0], "ip"):
            if len(words) >= 2 and self._matches(lowered[1], "address"):
                if len(words) == 3 and words[2].lower() == "dhcp":
                    if self._apply_dhcp_ip(interface):
                        interface.dhcp_enabled = True
                        interface.dhcp_setroute = False
                        interface.configured_ip = None
                        interface.configured_mask = None
                elif len(words) == 4 and words[2].lower() == "dhcp" and words[3].lower() == "setroute":
                    if self._apply_dhcp_ip(interface):
                        interface.dhcp_enabled = True
                        interface.dhcp_setroute = True
                        interface.configured_ip = None
                        interface.configured_mask = None
                elif len(words) == 4 and self._valid_ipv4(words[2]) and mask_to_prefix(words[3]) is not None:
                    if self._apply_static_ip(interface, words[2], words[3]):
                        interface.configured_ip = words[2]
                        interface.configured_mask = words[3]
                        interface.dhcp_enabled = False
                        interface.dhcp_setroute = False
                elif len(words) < 4:
                    print("% Incomplete command.")
                else:
                    print("% Invalid IP address or subnet mask.")
                return True, False

        if self._matches(lowered[0], "shutdown"):
            if len(words) != 1:
                self._print_invalid_marker(line, line.lower().find(words[1].lower()))
            elif self._apply_interface_admin_state(interface, enabled=False):
                interface.shutdown = True
            return True, False

        if self._matches(lowered[0], "no"):
            if len(words) < 2:
                print("% Incomplete command.")
                return True, False
            if len(words) != 2:
                self._print_invalid_marker(line, line.lower().find(words[2].lower()))
                return True, False
            target = lowered[1]
            if self._matches(target, "shutdown"):
                if self._apply_interface_admin_state(interface, enabled=True):
                    interface.shutdown = False
            elif self._matches(target, "description"):
                interface.description = f"Windows adapter: {interface.windows_name}"
            elif self._matches(target, "nameif"):
                interface.nameif = None
            elif self._matches(target, "security-level"):
                interface.security_level = None
            elif self._matches(target, "ip"):
                if self._apply_dhcp_ip(interface):
                    interface.configured_ip = None
                    interface.configured_mask = None
                    interface.dhcp_enabled = True
                    interface.dhcp_setroute = False
            else:
                self._print_invalid_marker(line, line.lower().find(words[1].lower()))
            return True, False

        return False, False

    def _resolve_interface_name(self, name: str) -> Optional[str]:
        lowered = name.lower()
        aliases = {key: key for key in self.interfaces}
        aliases.update(
            {
                interface.nameif.lower(): key
                for key, interface in self.interfaces.items()
                if interface.nameif
            }
        )
        matches = [alias for alias in aliases if alias.startswith(lowered)]
        if not matches:
            return None
        if len(matches) > 1 and lowered not in aliases:
            return None
        return aliases[lowered] if lowered in aliases else aliases[matches[0]]

    @staticmethod
    def _display_interface_name(interface: EmulatedInterface) -> str:
        return interface.nameif or interface.asa_name

    def _interface_name_for_route_ip(self, interface_ip: str) -> str:
        for interface in self.interfaces.values():
            if interface.effective_ip() == interface_ip:
                return self._display_interface_name(interface)
        return interface_ip

    def _interface_name_for_windows_name(self, windows_name: str) -> str:
        for interface in self.interfaces.values():
            if interface.windows_name.lower() == windows_name.lower():
                return self._display_interface_name(interface)
        return windows_name or "Unknown"

    @staticmethod
    def _is_interesting_connected_route(route: WindowsRoute) -> bool:
        if route.gateway.lower() != "on-link":
            return False
        if route.destination.startswith("127.") or route.destination.startswith("224."):
            return False
        if route.destination == "255.255.255.255" or route.mask == "240.0.0.0":
            return False
        if route.mask == "255.255.255.255":
            return False
        return True

    def _configure_route(self, words: List[str], negate: bool) -> None:
        if len(words) < 5:
            print("% Incomplete command.")
            return
        if len(words) > 6:
            self._print_invalid_marker(" ".join(words), len(" ".join(words[:6])) + 1)
            return

        interface_key = self._resolve_interface_name(words[1])
        if interface_key is None:
            print("% Invalid interface.")
            return

        destination, mask, gateway = words[2], words[3], words[4]
        metric = 1
        if len(words) > 5:
            try:
                metric = int(words[5])
            except ValueError:
                print("% Invalid route metric.")
                return
            if not 1 <= metric <= 255:
                print("% Route metric must be between 1 and 255.")
                return

        if not self._valid_ipv4(destination) or mask_to_prefix(mask) is None or not self._valid_ipv4(gateway):
            print("% Invalid route parameters.")
            return
        network = ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)
        if str(network.network_address) != destination:
            print("% Route destination must be a network address for the specified netmask.")
            return

        interface = self.interfaces[interface_key]
        interface_name = self._display_interface_name(interface)
        existing = [
            route for route in self.static_routes
            if route.interface_name == interface_name
            and route.destination == destination
            and route.mask == mask
            and route.gateway == gateway
        ]
        route = StaticRoute(
            interface_name=interface_name,
            destination=destination,
            mask=mask,
            gateway=gateway,
            metric=metric,
        )

        if negate:
            if existing:
                if self._apply_route(interface, existing[0], negate=True):
                    self.static_routes = [route for route in self.static_routes if route not in existing]
            else:
                print("% Route not found.")
            return

        if existing:
            if existing[0].metric == metric:
                return
            if self._apply_route(interface, existing[0], negate=True):
                if self._apply_route(interface, route, negate=False):
                    existing[0].metric = metric
                elif not self._apply_route(interface, existing[0], negate=False):
                    print("% Warning: route metric update failed and the original route could not be restored.")
            return

        if self._apply_route(interface, route, negate=False):
            self.static_routes.append(route)

    @staticmethod
    def _valid_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    def _show_hostname(self) -> None:
        print(self.hostname)

    def _show_version(self) -> None:
        print("Cisco Adaptive Security Appliance Software Version 9.18(Windows-Emulated)")
        print("Device Manager Version 7.20(1)")
        print()
        print(f"Hostname: {self.hostname}")
        print(f"Username: {self.username}")
        print(f"Windows OS: {get_os_caption()}")
        print(f"Kernel: {platform.release()} ({platform.version()})")
        print(f"Architecture: {platform.machine()}")
        print(f"Uptime: {get_uptime_string()}")
        print(f"Primary IPv4: {get_primary_ipv4()}")
        print(f"Compiled on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def _show_inventory(self) -> None:
        print(f'NAME: "{self.hostname}", DESCR: "Windows ASA CLI Emulator Host"')
        print(f'PID: {get_model()}, VID: 1.0, SN: {get_serial_number()}')
        print()
        print(f'MANUFACTURER: {get_manufacturer()}')
        print(f'MEMORY: {get_total_memory_gb()} GB RAM')
        print(f'CPU: {platform.processor() or "Unknown"}')

    def _show_cpu(self) -> None:
        snapshot = get_cpu_snapshot()
        usage = snapshot.get("usage_percent")
        processors = int(snapshot.get("logical_processors", 0))

        print("CPU utilization for 5 seconds = N/A; 1 minute: N/A; 5 minutes: N/A")
        print(f"Current sampled CPU busy = {usage:.2f}%" if usage is not None else "Current sampled CPU busy = Unknown")
        print(f"Logical processors      = {processors or 'Unknown'}")
        print(f"Processor               = {platform.processor() or 'Unknown'}")

    def _show_cpu_detail(self, limit: int = 10) -> None:
        self._show_cpu()
        processes = get_top_cpu_processes(limit)
        print()
        print(f"Top {limit} processes by sampled CPU utilization:")
        print("Process                          PID      CPU%  Working Set")
        if not processes:
            print("Process CPU detail unavailable")
            return
        for process in processes:
            name = str(process.get("ProcessName", "Unknown"))
            process_id = process.get("Id", "-")
            cpu_percent = float(process.get("CpuPercent", 0.0))
            working_set = float(process.get("WorkingSetMB", 0.0))
            print(f"{name[:30]:30} {str(process_id):>7} {cpu_percent:8.1f}% {working_set:10.1f} MB")

    def _show_memory(self) -> None:
        snapshot = get_memory_snapshot()
        if not snapshot:
            print("Memory statistics unavailable")
            return

        print(f"Total physical memory   : {snapshot['total_gb']:.2f} GB")
        print(f"Used physical memory    : {snapshot['used_gb']:.2f} GB")
        print(f"Free physical memory    : {snapshot['available_gb']:.2f} GB")
        print(f"Memory load             : {snapshot['load_percent']:.0f}%")
        print(f"Total virtual memory    : {snapshot['total_virtual_gb']:.2f} GB")
        print(f"Free virtual memory     : {snapshot['available_virtual_gb']:.2f} GB")

    def _show_memory_detail(self, limit: int = 10) -> None:
        self._show_memory()
        processes = get_top_memory_processes(limit)
        print()
        print(f"Top {limit} processes by working-set memory:")
        print("Process                          PID  Working Set  Paged Memory  Handles")
        if not processes:
            print("Process memory detail unavailable")
            return
        for process in processes:
            name = str(process.get("ProcessName", "Unknown"))
            process_id = process.get("Id", "-")
            working_set = float(process.get("WorkingSetMB", 0.0))
            paged_memory = float(process.get("PagedMemoryMB", 0.0))
            handles = process.get("Handles", "-")
            print(
                f"{name[:30]:30} {str(process_id):>7} {working_set:10.1f} MB "
                f"{paged_memory:10.1f} MB {str(handles):>8}"
            )

    def _show_interface_ip_brief(self) -> None:
        print("Interface              IP-Address      OK? Method Status                Protocol")
        if not self.interfaces:
            print("No interfaces discovered")
            return

        for interface in self.interfaces.values():
            ipv4 = interface.effective_ip() or "unassigned"
            method = interface.effective_method()
            status = "administratively down" if interface.shutdown else "up"
            protocol = "down" if interface.shutdown else "up"
            print(
                f"{interface.asa_name[:22]:22} "
                f"{ipv4[:15]:15} "
                f"YES "
                f"{method:6} "
                f"{status:21} "
                f"{protocol}"
            )

    def _show_system(self) -> None:
        print(f"Hostname        : {self.hostname}")
        print(f"FQDN/Domain     : {get_domain()}")
        print(f"OS              : {get_os_caption()}")
        print(f"Model           : {get_model()}")
        print(f"Manufacturer    : {get_manufacturer()}")
        print(f"Serial Number   : {get_serial_number()}")
        print(f"Total Memory GB : {get_total_memory_gb()}")
        print(f"User            : {self.username}")
        print(f"Working Dir     : {os.getcwd()}")

    def _show_route(self) -> None:
        print("Codes: C - connected, S - static, S* - candidate default")
        windows_routes = get_windows_ipv4_routes()
        printed_routes = set()

        for route in windows_routes:
            if self._is_interesting_connected_route(route):
                interface_name = self._interface_name_for_route_ip(route.interface_ip)
                key = ("C", route.destination, route.mask, interface_name)
                if key in printed_routes:
                    continue
                printed_routes.add(key)
                print(f"C    {route.destination} {route.mask} is directly connected, {interface_name}")

        for route in self.static_routes:
            if route.metric == 0:
                continue
            code = "S*" if route.destination == "0.0.0.0" and route.mask == "0.0.0.0" else "S "
            key = (code, route.destination, route.mask, route.gateway, route.interface_name)
            if key in printed_routes:
                continue
            printed_routes.add(key)
            print(
                f"{code}   {route.destination} {route.mask} "
                f"[1/{route.metric}] via {route.gateway}, {route.interface_name}"
            )

        for route in windows_routes:
            if route.gateway.lower() == "on-link":
                continue
            if route.destination.startswith("127.") or route.destination.startswith("224."):
                continue
            code = "S*" if route.destination == "0.0.0.0" and route.mask == "0.0.0.0" else "S "
            interface_name = self._interface_name_for_route_ip(route.interface_ip)
            key = (code, route.destination, route.mask, route.gateway, interface_name)
            if key in printed_routes:
                continue
            printed_routes.add(key)
            print(
                f"{code}   {route.destination} {route.mask} "
                f"[1/{route.metric}] via {route.gateway}, {interface_name}"
            )

    def _show_running_config(self) -> None:
        print(": Saved")
        print(":")
        print(f": Generated by Python ASA CLI emulator on {datetime.now().isoformat(sep=' ', timespec='seconds')}")
        print(":")
        print("ASA Version 9.18(Windows-Emulated)")
        print(f"hostname {self.hostname}")
        print(f"domain-name {get_domain()}")
        print("enable password ***** encrypted")
        print("passwd ***** encrypted")
        print("names")
        print("no mac-address auto")
        print(f"clock timezone LOCAL {datetime.now().astimezone().tzname() or 'LOCAL'}")
        print(f"username {self.username} privilege 15")
        print("!")
        print(f"! Windows host: {get_os_caption()}")
        print(f"! Manufacturer: {get_manufacturer()}")
        print(f"! Model: {get_model()}")
        print(f"! Serial: {get_serial_number()}")
        print(f"! Physical memory (GB): {get_total_memory_gb()}")
        print("!")

        self._show_running_interfaces()
        self._show_running_routes()
        print("service-policy global_policy global")

    def _show_running_interface_block(self, interface: EmulatedInterface) -> None:
        print(f"interface {interface.asa_name}")
        print(f" description {interface.description}")
        print(f" mac-address {interface.mac_address}")
        if interface.nameif:
            print(f" nameif {interface.nameif}")
        if interface.security_level is not None:
            print(f" security-level {interface.security_level}")
        if interface.dhcp_enabled:
            suffix = " setroute" if interface.dhcp_setroute else ""
            print(f" ip address dhcp{suffix}")
        elif interface.configured_ip and interface.configured_mask:
            print(f" ip address {interface.configured_ip} {interface.configured_mask}")
        elif interface.live_ipv4:
            print(f" ip address {interface.live_ipv4} 255.255.255.255")
        else:
            print(" no ip address")
        if interface.shutdown:
            print(" shutdown")
        else:
            print(" no shutdown")
        print("!")

    def _show_running_interfaces(self) -> None:
        for interface in self.interfaces.values():
            self._show_running_interface_block(interface)

    def _show_running_routes(self) -> None:
        routes = [route for route in self.static_routes if route.metric != 0]
        if not routes:
            print("! No static routes configured")
            return
        for route in routes:
            print(f"route {route.interface_name} {route.destination} {route.mask} {route.gateway} {route.metric}")


    def _running_config_text(self) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            self._show_running_config()
        return output.getvalue().rstrip()

    def _show_clock_detail(self) -> None:
        now = datetime.now().astimezone()
        print(now.strftime("%H:%M:%S.%f")[:-3] + " " + now.tzname() + " " + now.strftime("%a %b %d %Y"))
        print(f"Time source is Windows system clock")
        print(f"UTC offset is {now.strftime('%z')}")

    def _show_startup_config(self) -> None:
        if self.startup_config_text is None:
            print("% No startup configuration has been saved.")
            return
        print(self.startup_config_text)

    def _show_module_detail(self) -> None:
        print('Mod  Card Type                                    Model              Serial No.')
        print(f'1    Windows ASA CLI Emulator Host                {get_model()[:18]:18} {get_serial_number()}')
        print()
        print('Mod  MAC Address Range                 Hw Version   Fw Version   Sw Version')
        first_mac = next((interface.mac_address for interface in self.interfaces.values()), "unassigned")
        print(f'1    {first_mac:33} 1.0          N/A          9.18(Emulated)')

    def _show_interfaces_detail(self) -> None:
        if not self.interfaces:
            print("No interfaces discovered")
            return

        for interface in self.interfaces.values():
            self._show_interface_detail(interface)

    def _show_interface_detail(self, interface: EmulatedInterface) -> None:
        status = "administratively down" if interface.shutdown else "up"
        protocol = "down" if interface.shutdown else "up"
        ip_address = interface.effective_ip() or "unassigned"
        mask = interface.configured_mask or ("DHCP" if interface.dhcp_enabled else "255.255.255.255")
        print(f"Interface {interface.asa_name} \"{self._display_interface_name(interface)}\", is {status}, line protocol is {protocol}")
        print(f"  Windows adapter: {interface.windows_name}")
        print("  Hardware is Windows adapter, BW 1000000 Kbit, DLY 10 usec")
        print(f"  Description: {interface.description}")
        print(f"  MAC address {interface.mac_address}, MTU 1500")
        print(f"  IP address {ip_address}, subnet mask {mask}")
        print(f"  Method {interface.effective_method()}, security level {interface.security_level if interface.security_level is not None else 'unset'}")
        print("  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0")
        print("  5 minute input rate 0 bits/sec, 0 packets/sec")
        print("  5 minute output rate 0 bits/sec, 0 packets/sec")
        print()

    def _show_ip_address(self) -> None:
        print("System IP Addresses:")
        for interface in self.interfaces.values():
            ip_address = interface.effective_ip() or "unassigned"
            method = interface.effective_method()
            print(f"  {self._display_interface_name(interface):18} {ip_address:15} {method}")

    def _show_route_summary(self) -> None:
        windows_routes = get_windows_ipv4_routes()
        connected = sum(1 for route in windows_routes if self._is_interesting_connected_route(route))
        static = sum(1 for route in self.static_routes if route.metric != 0)
        static += sum(1 for route in windows_routes if route.gateway.lower() != "on-link")
        print("Route Source    Networks    Subnets     Overhead    Memory (bytes)")
        print(f"connected       {connected:<11}0           0           {connected * 128}")
        print(f"static          {static:<11}0           0           {static * 128}")
        print(f"total           {connected + static:<11}0           0           {(connected + static) * 128}")

    def _show_arp(self) -> None:
        print("Protocol  Address          Age (min)  Hardware Addr   Type  Interface")
        entries = get_windows_arp_entries()
        if not entries:
            print("No ARP entries discovered")
            return

        for entry in entries:
            mac_address = f"{entry.mac_address[:4]}.{entry.mac_address[4:8]}.{entry.mac_address[8:]}"
            interface_name = self._interface_name_for_windows_name(entry.interface_alias)
            entry_type = "ARPA" if entry.state.lower() != "permanent" else "ARPA static"
            print(f"Internet  {entry.address:15}  -          {mac_address:14}  {entry_type:11} {interface_name}")

    def _show_conn_count(self) -> None:
        connections = get_windows_connections()
        tcp_count = sum(1 for connection in connections if connection.protocol == "TCP")
        udp_count = sum(1 for connection in connections if connection.protocol == "UDP")
        print(f"{len(connections)} in use, {len(connections)} most used")
        print(f"TCP conn count: {tcp_count}")
        print(f"UDP conn count: {udp_count}")

    def _show_xlate_count(self) -> None:
        print("0 in use, 0 most used")

    def _show_access_list(self) -> None:
        print("No access-list entries configured")

    def _show_nat_detail(self) -> None:
        print("Manual NAT Policies (Section 1)")
        print("  No rules configured")
        print("Auto NAT Policies (Section 2)")
        print("  No rules configured")
        print("After-auto NAT Policies (Section 3)")
        print("  No rules configured")

    def _show_service_policy(self) -> None:
        print("Global policy:")
        print("  Service-policy: global_policy")
        print("    Class-map: inspection_default")
        print("      Inspect: dns, packet 0, drop 0, reset-drop 0")

    def _show_processes(self) -> None:
        processes = get_windows_processes()
        print("PC         Thread     STATE       Runtime    SBASE     Stack Process")
        if not processes:
            print("Windows process information unavailable")
            return
        for process in processes:
            name = str(process.get("ProcessName", "Unknown"))
            process_id = int(process.get("Id", 0) or 0)
            runtime_ms = int(float(process.get("CPU", 0) or 0) * 1000)
            working_set = float(process.get("WorkingSetMB", 0) or 0)
            print(f"N/A        {process_id:>7}  Running  {runtime_ms:>12}  N/A  {working_set:>6.1f}MB {name[:40]}")

    def _show_processes_cpu_usage(self, non_zero: bool = False, sorted_output: bool = False) -> None:
        processes = get_top_cpu_processes(50)
        if non_zero:
            processes = [process for process in processes if float(process.get("CpuPercent", 0) or 0) > 0]
        if not sorted_output:
            processes = sorted(processes, key=lambda process: str(process.get("ProcessName", "")).lower())

        print("PC         Thread       5Sec     1Min     5Min   Process")
        if not processes:
            print("No Windows processes matched the CPU utilization filter")
            return
        for process in processes:
            name = str(process.get("ProcessName", "Unknown"))
            process_id = int(process.get("Id", 0) or 0)
            cpu_percent = float(process.get("CpuPercent", 0) or 0)
            print(f"N/A        {process_id:>8}  {cpu_percent:5.1f}%   N/A      N/A    {name[:40]}")

    def _show_processes_cpu_hog(self) -> None:
        processes = [
            process for process in get_top_cpu_processes(20)
            if float(process.get("CpuPercent", 0) or 0) > 0
        ]
        print("CPU hog statistics (Windows sampled CPU equivalent):")
        print("Process                          PID      CPU%")
        if not processes:
            print("No processes reported sampled CPU utilization")
            return
        for process in processes:
            print(
                f"{str(process.get('ProcessName', 'Unknown'))[:30]:30} "
                f"{int(process.get('Id', 0) or 0):>7} {float(process.get('CpuPercent', 0) or 0):8.1f}%"
            )

    def _show_processes_internals(self) -> None:
        processes = get_windows_processes()
        print("Process                          PID  Handles  Working Set")
        if not processes:
            print("Windows process information unavailable")
            return
        for process in processes:
            name = str(process.get("ProcessName", "Unknown"))
            process_id = int(process.get("Id", 0) or 0)
            handles = int(process.get("Handles", 0) or 0)
            working_set = float(process.get("WorkingSetMB", 0) or 0)
            print(f"{name[:30]:30} {process_id:>7} {handles:>8} {working_set:10.1f} MB")

    def _show_processes_memory(self) -> None:
        processes = get_top_memory_processes(50)
        print("Process                          PID  Working Set  Paged Memory  Handles")
        if not processes:
            print("Process memory information unavailable")
            return
        for process in processes:
            name = str(process.get("ProcessName", "Unknown"))
            process_id = int(process.get("Id", 0) or 0)
            working_set = float(process.get("WorkingSetMB", 0) or 0)
            paged_memory = float(process.get("PagedMemoryMB", 0) or 0)
            handles = int(process.get("Handles", 0) or 0)
            print(f"{name[:30]:30} {process_id:>7} {working_set:10.1f} MB {paged_memory:10.1f} MB {handles:>8}")

    @staticmethod
    def _format_connection_endpoint(address: str, port: int) -> str:
        return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

    @staticmethod
    def _connection_matches_address(address: str, specification: str, mask: Optional[str]) -> bool:
        try:
            target = ipaddress.ip_address(address)
            if mask:
                return target in ipaddress.IPv4Network(f"{specification}/{mask}", strict=False)
            if "-" in specification:
                lower, upper = (ipaddress.ip_address(value) for value in specification.split("-", 1))
                if target.version != lower.version:
                    return False
                return lower <= target <= upper
            return target == ipaddress.ip_address(specification)
        except ValueError:
            return False

    @staticmethod
    def _connection_matches_port(port: int, specification: str) -> bool:
        values = specification.split("-", 1)
        lower, upper = int(values[0]), int(values[-1])
        return lower <= port <= upper

    @staticmethod
    def _connection_matches_state(connection: WindowsConnection, state: str) -> bool:
        requested = state.lower().replace("-", "")
        actual = connection.state.lower().replace("-", "")
        if requested == "up":
            return actual in {"established", "active"}
        if requested == "tcpembryonic":
            return actual in {"synsent", "synreceived"}
        return actual == requested

    def _connection_matches_filters(self, connection: WindowsConnection, filters: ConnectionFilters) -> bool:
        if filters.protocols and connection.protocol not in filters.protocols:
            return False
        if filters.states and not any(self._connection_matches_state(connection, state) for state in filters.states):
            return False
        endpoints = [(connection.local_address, connection.local_port), (connection.remote_address, connection.remote_port)]
        if any(not any(self._connection_matches_address(address, specification, mask) for address, _ in endpoints) for specification, mask in filters.address_filters):
            return False
        if any(not any(self._connection_matches_port(port, specification) for _, port in endpoints) for specification in filters.port_filters):
            return False
        return True

    @staticmethod
    def _connection_flags(connection: WindowsConnection) -> str:
        if connection.protocol == "UDP":
            return "U"
        if connection.state.lower() == "established":
            return "UIO"
        if connection.state.lower() in {"synsent", "synreceived"}:
            return "i"
        return "-"

    def _show_connections(self, filters: Optional[ConnectionFilters] = None) -> None:
        filters = filters or ConnectionFilters()
        connections = [
            connection for connection in get_windows_connections()
            if self._connection_matches_filters(connection, filters)
        ]
        print(f"{len(connections)} in use, {len(connections)} most used")
        if not connections:
            print("No Windows connections matched the requested filters")
            return

        displayed = connections if filters.show_all else connections[:100]
        for connection in displayed:
            interface_name = self._interface_name_for_route_ip(connection.local_address)
            local = self._format_connection_endpoint(connection.local_address, connection.local_port)
            remote = self._format_connection_endpoint(connection.remote_address, connection.remote_port)
            print(
                f"{connection.protocol} {interface_name} {local} {remote}, "
                f"state {connection.state}, flags {self._connection_flags(connection)}, pid {connection.owning_process}"
            )
            if filters.detail or filters.long_format:
                print(f"  Local interface: {interface_name}; Windows state: {connection.state}; owning PID: {connection.owning_process}")
            if filters.detail:
                print(f"  Local endpoint: {local}; remote endpoint: {remote}; traffic counters: unavailable from Windows snapshot")
        if not filters.show_all and len(connections) > len(displayed):
            print(f"... {len(connections) - len(displayed)} additional connections omitted; use 'show conn all'")

    def _show_dns(self, detail: bool = False) -> None:
        servers = get_windows_dns_servers()
        print("Trusted DNS source configuration:")
        if not servers:
            print("  No IPv4 DNS servers are configured")
            return
        for server in servers:
            interface_name = self._interface_name_for_windows_name(server.interface_alias)
            if detail:
                print(f"  {server.address:15} interface {interface_name} ({server.interface_alias})")
            else:
                print(f"  {server.address:15} interface {interface_name}")

    def _show_blocks(self) -> None:
        print("SIZE    MAX    LOW    CNT")
        print("4       100    100    100")
        print("80      500    500    500")
        print("256     500    500    500")
        print("1550    1000   1000   1000")

    def _show_filesystems(self) -> None:
        root = os.path.abspath(os.sep)
        usage = shutil.disk_usage(root)
        print("File Systems:")
        print("  Size(b)       Free(b)       Type  Flags  Prefixes")
        print(f"  {usage.total:>16}  {usage.free:>16}  disk  rw     disk0: flash:")
        print()
        print("Directory of disk0:/")
        for entry in sorted(os.scandir(os.getcwd()), key=lambda item: item.name.lower()):
            entry_type = "d" if entry.is_dir() else "-"
            size = 0 if entry.is_dir() else entry.stat().st_size
            print(f"{entry_type} {size:>10}  {entry.name}")

    def _show_logging_tail(self) -> None:
        print("Syslog logging: enabled (emulated)")
        print("Buffer logging: level debugging, 5 messages logged")
        print(f"%ASA-6-302013: Built emulated management connection for user {self.username}")
        print("%ASA-6-302014: Teardown emulated management connection")
        print("%ASA-5-111008: User executed the show tech-support command")
        print("%ASA-4-411001: Line protocol state changes are reflected from Windows adapters")
        print("%ASA-6-199013: Emulator diagnostic collection complete")

    def _show_resource_usage(self) -> None:
        print("Resource                 Current        Peak      Limit        Denied")
        print(f"Interfaces               {len(self.interfaces):<14}{len(self.interfaces):<10}N/A          0")
        route_count = sum(1 for route in self.static_routes if route.metric != 0)
        print(f"Routes                   {route_count:<14}{route_count:<10}N/A          0")
        print("Conns                    0              0         N/A          0")
        print("Xlates                   0              0         N/A          0")
        print("Syslogs                  5              5         N/A          0")

    def _show_failover(self) -> None:
        print("Failover Off")
        print("This host is operating as a standalone ASA emulator")

    def _show_vpn_stats(self) -> None:
        print("IKEv1 SAs: 0")
        print("IKEv2 SAs: 0")
        print("IPsec SAs: 0")
        print("SSL VPN sessions: 0")

    def _show_asp_drop(self) -> None:
        print("Frame drop:")
        print("  No ASP drop counters are available in the Windows emulator")

    def _show_environment(self) -> None:
        print("Power Supply: N/A")
        print("Temperature: N/A")
        print("Fans: N/A")
        print(f"Host platform: {get_manufacturer()} {get_model()}")

    def _show_history(self) -> None:
        if not self.history:
            print("No command history")
            return
        for index, command in enumerate(self.history[-20:], start=1):
            print(f"{index:>3}  {command}")

    def _tech_section(self, command: str, action: Callable[[], None]) -> None:
        print()
        print("=" * 72)
        print(f"{self.hostname}# {command}")
        print("=" * 72)
        action()

    def _show_tech_bundle(self, include_sensitive: bool) -> None:
        print("Cisco Adaptive Security Appliance show tech-support")
        print("Output captured by ASA CLI emulator for Windows")
        print(f"Generated: {datetime.now().astimezone().isoformat(sep=' ', timespec='seconds')}")
        print("Passwords and secret values are removed by default.")

        sections: List[Tuple[str, Callable[[], None]]] = [
            ("show clock detail", self._show_clock_detail),
            ("show version", self._show_version),
            ("show inventory", self._show_inventory),
            ("show module detail", self._show_module_detail),
            ("show running-config", self._show_running_config),
            ("show startup-config", self._show_startup_config),
            ("show interface ip brief", self._show_interface_ip_brief),
            ("show interfaces", self._show_interfaces_detail),
            ("show ip address", self._show_ip_address),
            ("show route", self._show_route),
            ("show route-summary", self._show_route_summary),
            ("show conn count", self._show_conn_count),
            ("show xlate count", self._show_xlate_count),
            ("show access-list", self._show_access_list),
            ("show nat detail", self._show_nat_detail),
            ("show service-policy", self._show_service_policy),
            ("show cpu detail", self._show_cpu),
            ("show processes cpu-usage non-zero sorted", lambda: self._show_processes_cpu_usage(non_zero=True, sorted_output=True)),
            ("show memory detail", self._show_memory),
            ("show blocks", self._show_blocks),
            ("show logging", self._show_logging_tail),
            ("show resource usage count all 1", self._show_resource_usage),
            ("show failover", self._show_failover),
            ("show vpn-sessiondb summary", self._show_vpn_stats),
            ("show crypto ikev1 stats", self._show_vpn_stats),
            ("show asp drop", self._show_asp_drop),
            ("show environment", self._show_environment),
        ]

        if include_sensitive:
            sections.extend(
                [
                    ("show arp", self._show_arp),
                    ("show processes memory", self._show_processes_memory),
                    ("dir all-filesystems", self._show_filesystems),
                    ("show history", self._show_history),
                ]
            )

        for command, action in sections:
            self._tech_section(command, action)

    def _show_tech(self) -> None:
        self._show_tech_bundle(include_sensitive=True)

    def _show_tech_sanitized(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self._show_tech_bundle(include_sensitive=False)
        print(self._sanitize_tech_output(output.getvalue()).rstrip())

    def _sanitize_tech_output(self, output: str) -> str:
        sanitized = output.replace(self.hostname, "<redacted-host>")
        sanitized = sanitized.replace(self.username, "<redacted-user>")
        sanitized = sanitized.replace(os.getcwd(), "<redacted-path>")
        sanitized = re.sub(r"(?im)^(.*(?:serial number|serial:|\bSN:).*)$", "<redacted-serial>", sanitized)
        sanitized = re.sub(r"(?im)^\s*(?:description|Description:).*?$", "  <redacted-description>", sanitized)
        sanitized = re.sub(r"(?im)^Working Dir\s*:.*$", "Working Dir     : <redacted-path>", sanitized)
        sanitized = re.sub(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "<redacted-mac>", sanitized)

        def mask_ip(match: re.Match[str]) -> str:
            value = match.group(0)
            return value if value in {"0.0.0.0", "255.255.255.255"} else "<redacted-ip>"

        return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", mask_ip, sanitized)

    @staticmethod
    def _asa_interface_name(index: int, source_name: str) -> str:
        lowered = source_name.lower()
        if "wireless" in lowered or "wi-fi" in lowered:
            return f"management{index}/0"
        return f"GigabitEthernet{index}/0"


def main() -> int:
    if os.name != "nt":
        print("This emulator is intended for Windows hosts.")
    cli = AsaCli()
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\nLogoff")
    return 0


if __name__ == "__main__":
    sys.exit(main())
