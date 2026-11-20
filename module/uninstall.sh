#!/system/bin/sh
MODDIR=${0%/*}
STATE=/data/adb/vanta-mcp
sh "$MODDIR/stop.sh"
if [ -f "$STATE/original-usb" ]; then
  original=$(cat "$STATE/original-usb")
  case "$original" in mtp|ptp|midi|rndis|ncm|mtp,adb|ptp,adb|midi,adb|rndis,adb|ncm,adb) setprop sys.usb.config "$original" ;; esac
fi
# Only this module's fixed, private state directory is removed.
rm -rf /data/adb/vanta-mcp
