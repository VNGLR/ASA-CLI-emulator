# ASA CLI Emulator

A dependency-free Python CLI that presents native Windows or Linux networking and system information through an ASA-inspired command interface.

## Run

### Windows

Run the Windows version from an elevated PowerShell session when using commands that change networking:

```powershell
python .\asa_cli_emulator_windows.py
```

### Linux

Run the Linux version with `sudo` when using commands that change networking:

```bash
sudo python3 ./asa_cli_emulator.py
```

Linux support expects `ip` and `ss` from `iproute2`, plus `ps` from `procps`. DHCP configuration also needs `dhclient` when that command is used.

Read-only commands work without elevation. Commands such as `shutdown`, `no shutdown`, `ip address`, and `route` require Administrator/root privileges and apply to the selected host interface immediately.

Both versions provide `port tester <hostname-or-ip> <port>`, which uses Python's built-in TCP socket support to test reachability without an external client. For example: `port tester google.com 443`.

## Live Configuration

The following commands affect the host:

```text
configure terminal
interface GigabitEthernet1/0
shutdown
no shutdown
ip address 192.0.2.10 255.255.255.0
ip address dhcp
route GigabitEthernet1/0 198.51.100.0 255.255.255.0 192.0.2.1 1
no route GigabitEthernet1/0 198.51.100.0 255.255.255.0 192.0.2.1 1
```

On Windows, static routes are installed in the persistent route store. On Linux, addresses and routes are applied immediately through `ip`; persist them across reboot using the distribution's network manager, such as NetworkManager or systemd-networkd. A static IP command does not configure a gateway; configure the gateway separately with a `route` command. Changing an IP address or disabling the interface currently carrying the terminal session can disconnect the host.

`write memory` stores the emulator's ASA-style configuration snapshot in `.asa-cli-emulator-config.json` on Windows or `.asa-cli-emulator-linux-config.json` on Linux. These files are ignored by Git because they can contain local names, interface aliases, and network configuration. They preserve the startup-config display, emulator-only metadata, and managed routes across launches; live IP, DHCP, and interface state are always rediscovered from the host and are never replayed automatically.

## Useful Commands

```text
show version
show interface ip brief
show interface GigabitEthernet1/0
show cpu detail
show cpu detail 5
show memory detail
show mem detail 5
show arp
show processes
show processes cpu-usage non-zero sorted
show processes memory
show conn
show conn count
show conn protocol tcp state up
show conn address 192.0.2.10-192.0.2.20 port 443 detail
show conn all
show dns
show dns trusted-source detail
show route
show running-config
show run interface
show run interface GigabitEthernet1/0
show run route
ping 192.0.2.1
ping example.com 3
traceroute 192.0.2.1
trace route example.com 8
port tester google.com 443
show system > system.txt
show startup-config
show tech-support
show tech sanitized
```

`show tech-support` includes local host diagnostics. Use `show tech sanitized` before sharing output: it removes the most sensitive sections and masks host/user identifiers, paths, serials, MAC addresses, and IP addresses.

`>` saves output from a `show` command to a UTF-8 file in the current directory, for example `show system > system.txt`.

## Tests

```bash
python -m unittest -v
```
