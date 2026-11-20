#!/system/bin/sh
MODDIR=${0%/*}
STATE=/data/adb/vanta-mcp
umask 077
mkdir -p "$STATE"
chmod 700 "$STATE"
[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/remove" ] && exit 0
[ -f "$STATE/server.key" ] && [ -f "$STATE/server.pem" ] && [ -f "$STATE/ca.pem" ] || exit 1
if [ -f "$STATE/daemon.pid" ]; then
  old=$(cat "$STATE/daemon.pid")
  case "$old" in ''|*[!0-9]*) ;; *)
    exe=$(readlink "/proc/$old/exe")
    case "$exe" in /data/adb/modules/vanta_mcp/bin/vantad|/data/adb/modules_update/vanta_mcp/bin/vantad) kill -0 "$old" 2>/dev/null && exit 0 ;; esac
  esac
fi
# A normal KernelSU late-start service. It can be disabled/removed in Manager.
while [ "$(getprop sys.boot_completed)" != 1 ]; do
  [ -f "$MODDIR/disable" ] && exit 0
  [ -f "$MODDIR/remove" ] && exit 0
  sleep 2
done
[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/remove" ] && exit 0
if [ ! -s "$STATE/original-usb" ]; then getprop sys.usb.state > "$STATE/original-usb"; fi
# The daemon owns recovery and can start before the USB cable is attached.
chmod 600 "$STATE/"*.key "$STATE/"*.pem "$STATE/server.json"
nohup "$MODDIR/bin/vantad" --state "$STATE" --module "$MODDIR" >> "$STATE/service.log" 2>&1 &
echo $! > "$STATE/daemon.pid"
