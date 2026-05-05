import ctypes
import getpass
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
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
        self.user_tree, self.enabled_tree, self.config_tree, self.interface_tree = self._build_command_trees()

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
            self._add_command(root, ["show", "cpu"], "Display processor utilization", self._show_cpu)
            self._add_command(root, ["show", "memory"], "Display memory utilization", self._show_memory)
            self._add_command(root, ["show", "mem"], "Display memory utilization", self._show_memory)
            self._add_command(root, ["show", "tech"], "Display technical support information", self._show_tech)
            self._add_command(root, ["show", "version"], "System software information", self._show_version)
            self._add_command(root, ["show", "running-config"], "Current operating configuration", self._show_running_config)
            self._add_command(root, ["show", "inventory"], "Hardware and platform inventory", self._show_inventory)
            self._add_command(root, ["show", "hostname"], "Display the device hostname", self._show_hostname)
            self._add_command(root, ["show", "system"], "Display host system information", self._show_system)
            self._add_command(root, ["show", "interface", "ip", "brief"], "Interface IP status and configuration", self._show_interface_ip_brief)
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

        if line.strip() == "?":
            self._print_help_for_prefix("")
            return False

        if "?" in line:
            self._handle_question_mark(line)
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
            "store=active",
        ]
        if not negate:
            command.insert(-1, f"metric={route.metric}")

        ok, output = run_live_command(command)
        if not ok:
            self._print_windows_error(output)
        return ok

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
        if self.config_submode == "config":
            if words and self._matches(words[0], "interface"):
                return self._complete_value_command(buffer, words, trailing_space, list(self.interfaces))
            if words and self._matches(words[0], "route"):
                return self._complete_value_command(buffer, words, trailing_space, list(self.interfaces))
            if words and self._matches(words[0], "no") and len(words) > 1 and self._matches(words[1], "route"):
                return self._complete_value_command(buffer, words, trailing_space, list(self.interfaces), offset=1)
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

    @staticmethod
    def _complete_last_word(words: List[str], options: List[str], append_space: bool) -> Tuple[str, List[str]]:
        current = words[-1].lower()
        matches = sorted(option for option in options if option.startswith(current))
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
            else:
                interface.nameif = words[1]
            return True, False

        if self._matches(lowered[0], "security-level"):
            if len(words) < 2:
                print("% Incomplete command.")
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
                if len(words) < 4:
                    if len(words) == 3 and self._matches(words[2].lower(), "dhcp"):
                        if self._apply_dhcp_ip(interface):
                            interface.dhcp_enabled = True
                            interface.dhcp_setroute = False
                            interface.configured_ip = None
                            interface.configured_mask = None
                    else:
                        print("% Incomplete command.")
                elif self._matches(words[2].lower(), "dhcp"):
                    setroute = len(words) > 3 and self._matches(words[3].lower(), "setroute")
                    if self._apply_dhcp_ip(interface):
                        interface.dhcp_enabled = True
                        interface.dhcp_setroute = setroute
                        interface.configured_ip = None
                        interface.configured_mask = None
                elif self._valid_ipv4(words[2]) and mask_to_prefix(words[3]) is not None:
                    if self._apply_static_ip(interface, words[2], words[3]):
                        interface.configured_ip = words[2]
                        interface.configured_mask = words[3]
                        interface.dhcp_enabled = False
                        interface.dhcp_setroute = False
                else:
                    print("% Invalid IP address or subnet mask.")
                return True, False

        if self._matches(lowered[0], "shutdown"):
            if self._apply_interface_admin_state(interface, enabled=False):
                interface.shutdown = True
            return True, False

        if self._matches(lowered[0], "no"):
            if len(words) < 2:
                print("% Incomplete command.")
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

    def _configure_route(self, words: List[str], negate: bool) -> None:
        if len(words) < 5:
            print("% Incomplete command.")
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

        if not all(self._valid_ipv4(value) for value in (destination, mask, gateway)):
            print("% Invalid route parameters.")
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
            if self._apply_route(interface, existing[0], negate=True) and self._apply_route(interface, route, negate=False):
                existing[0].metric = metric
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
        print("Codes: C - connected, S - static")
        for interface in self.interfaces.values():
            ip_address = interface.effective_ip()
            if ip_address and not interface.shutdown:
                print(f"C    {ip_address} 255.255.255.255 is directly connected, {self._display_interface_name(interface)}")
        for route in self.static_routes:
            if route.metric == 0:
                continue
            print(
                f"S    {route.destination} {route.mask} "
                f"[{route.metric}/0] via {route.gateway}, {route.interface_name}"
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

        for interface in self.interfaces.values():
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

        for route in self.static_routes:
            if route.metric == 0:
                continue
            print(f"route {route.interface_name} {route.destination} {route.mask} {route.gateway} {route.metric}")
        print("service-policy global_policy global")

    def _show_tech(self) -> None:
        print("------------------ show tech-support ------------------")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        print("---------- show version ----------")
        self._show_version()
        print()
        print("---------- show inventory ----------")
        self._show_inventory()
        print()
        print("---------- show cpu ----------")
        self._show_cpu()
        print()
        print("---------- show memory ----------")
        self._show_memory()
        print()
        print("---------- show system ----------")
        self._show_system()
        print()
        print("---------- show interface ip brief ----------")
        self._show_interface_ip_brief()
        print()
        print("---------- show route ----------")
        self._show_route()
        print()
        print("---------- show running-config ----------")
        self._show_running_config()

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
