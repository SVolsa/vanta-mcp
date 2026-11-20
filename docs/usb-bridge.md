# Experimental paired USB bridge

This is an optional transport for an ARM64 Android test device with KernelSU Next and a Windows desktop. Standard ADB users can follow the main README. The bridge creates an owner-paired TLS session over the USB network interface and may change the Android USB function while active.

## Build

Install Python 3 and Go according to Go's supported release policy, then run `python build_module.py`. The ZIP is written under `out/usb-*`. Install the ZIP with the KernelSU Next manager on a test device and provision pairing files.

## Pair

Run `go -C device run . pair --dir /absolute/private/path/to/pairing` on the host. Choose a location under your private user directory. The command creates a new directory and prints errors if it cannot create the pairing. Keep the host client key and JSON private. The device needs `ca.pem`, `server.pem`, `server.key` and `server.json` in root-owned `/data/adb/vanta-mcp`. Provision with permissions `0700` on that directory and `0600` on the files through an existing, authorized administrative connection.

Point the MCP server at the generated `client.json` with `VANTA_CONFIG` and use `VANTA_TRANSPORT=usb`. The standard Windows lookup path is `%APPDATA%\vanta-mcp\usb\client.json`. Configured client certificate, CA and key paths can be absolute or relative to the config file.

The module can be disabled or removed through KernelSU Next. A stopped or disabled service cannot accept new connections. After rotating a pairing, provision the new device files and restart the enabled module.

## Verification limits

The 0.4.4 bridge has ARM64 request-handler and permission-isolation evidence. A previous 0.4.3 installation supplied the persistent USB compatibility baseline. Fresh 0.4.4 installation, restart, unattended reconnect and Device Use over USB require acceptance on the intended device, ROM, cable and Windows driver.
