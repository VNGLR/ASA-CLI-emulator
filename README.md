# Windows ASA CLI Emulator

A dependency-free Python CLI that presents Windows networking and system information through an ASA-inspired command interface.

## Run

Run from an elevated PowerShell session when using commands that change Windows networking:

```powershell
python .\asa_cli_emulator.py
```

Read-only commands work without elevation. Commands such as `shutdown`, `no shutdown`, `ip address`, and `route` require Administrator privileges and apply to the selected Windows adapter immediately.

## Live Configuration

The following commands affect the Windows host:

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

Static routes are installed in the Windows persistent route store. A static IP command does not configure a gateway; configure the gateway separately with a `route` command. Changing an IP address or disabling the adapter currently carrying the terminal session can disconnect the host.

`write memory` stores the emulator's ASA-style configuration snapshot in `.asa-cli-emulator-config.json`. That file is ignored by Git because it can contain local names, interface aliases, and network configuration. It preserves the startup-config display, emulator-only metadata, and managed routes across launches; live IP, DHCP, and adapter state are always rediscovered from Windows and are never replayed automatically.

## Useful Commands

```text
show version
show interface ip brief
show route
show running-config
show startup-config
show tech-support
show tech sanitized
```

`show tech-support` includes local host diagnostics. Use `show tech sanitized` before sharing output: it removes the most sensitive sections and masks host/user identifiers, paths, serials, MAC addresses, and IP addresses.

## Tests

```powershell
python -m unittest -v
```
