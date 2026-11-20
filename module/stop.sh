#!/system/bin/sh
STATE=/data/adb/vanta-mcp
if [ -f "$STATE/daemon.pid" ]; then
  pid=$(cat "$STATE/daemon.pid")
  case "$pid" in ''|*[!0-9]*) ;; *)
    exe=$(readlink "/proc/$pid/exe")
    case "$exe" in /data/adb/modules/vanta_mcp/bin/vantad|/data/adb/modules_update/vanta_mcp/bin/vantad)
      kill "$pid" 2>/dev/null
      for attempt in $(seq 1 8); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
      done
      # Recheck identity before forcing a stuck instance to stop.
      exe=$(readlink "/proc/$pid/exe")
      case "$exe" in /data/adb/modules/vanta_mcp/bin/vantad|/data/adb/modules_update/vanta_mcp/bin/vantad) kill -9 "$pid" 2>/dev/null ;; esac
      ;;
    esac
  esac
  rm -f "$STATE/daemon.pid"
fi
ip rule del priority 10500 from 169.254.77.1/32 to 169.254.0.0/16 lookup main 2>/dev/null
for item in /sys/class/net/rndis* /sys/class/net/usb* /sys/class/net/ncm*; do
  [ -e "$item" ] || continue
  iface=${item##*/}
  case "$iface" in rndis*) suffix=${iface#rndis} ;; usb*) suffix=${iface#usb} ;; ncm*) suffix=${iface#ncm} ;; *) continue ;; esac
  case "$suffix" in ''|*[!0-9]*) continue ;; esac
  ip addr del 169.254.77.1/16 dev "$iface" 2>/dev/null
done
exit 0
