#!/system/bin/sh
[ "$ARCH" = "arm64" ] || abort "Vanta requires ARM64"
[ "$KSU" = "true" ] || abort "Install with KernelSU Next"
ui_print "Vanta MCP USB Bridge: paired TLS over USB RNDIS"
ui_print "Pairing state: /data/adb/vanta-mcp (provision separately)"
ui_print "No system overlay or kernel patch is installed."
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/vantad" 0 0 0755
for script in service.sh action.sh stop.sh uninstall.sh; do
  set_perm "$MODPATH/$script" 0 0 0755
done
