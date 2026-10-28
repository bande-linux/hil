# Unbound Linux hardware-in-the-loop host

Runs on the Mac that has the target Mac on USB-C. `hil.daemon` owns the
device: one lease at a time, a boot runs the bootloader's
`proxyclient/tools/linux.py` through a relay, and every run's inputs, proxy
log and serial log are kept under `runs_dir/<run id>/`. `hil.mcp` exposes
`hil_lease`, `hil_boot`, `hil_log` and `hil_release` to agents over stdio.

The relay sits between `linux.py` and the USB device and parses every
request of the proxy protocol. A memory or MMIO write that touches a block
in the deny-list, a power-management or NVMe proxy call, or a call that
runs code on the device is not forwarded: the run ends as `blocked`. The
deny-list is derived from the device tree given as `dtb`: power management,
CPU frequency, SPMI (PMU), SMC, SEP, NVMe and the NVRAM flash controller,
with their mailboxes and SARTs.

## Running

```sh
cp hil.example.json hil.json
python3 -m hil.daemon --config hil.json
```

MCP client configuration:

```json
{"mcpServers": {"hil": {"command": "python3", "args": ["-m", "hil.mcp"], "cwd": "/path/to/hil"}}}
```

`python3 -m unittest -v tests.test_hil` runs the tests against a stub
device; set `PROXYCLIENT` to the bootloader's `proxyclient/` to also check
the frames the real proxyclient sends.
