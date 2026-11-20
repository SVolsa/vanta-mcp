#!/system/bin/sh
MODDIR=${0%/*}
STATE=/data/adb/vanta-mcp
if [ -f "$STATE/daemon.pid" ] && kill -0 "$(cat "$STATE/daemon.pid")" 2>/dev/null; then
  sh "$MODDIR/stop.sh"
  echo "Vanta USB stopped"
else
  sh "$MODDIR/service.sh"
  echo "Vanta USB start requested"
fi
