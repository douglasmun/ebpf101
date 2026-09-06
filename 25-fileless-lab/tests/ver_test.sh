#!/bin/sh
# isolate the doc's version-comparison logic
t(){ kver="$1"
  maj=${kver%%.*}; rest=${kver#*.}; min=${rest%%.*}
  if [ "$maj" -gt 6 ] 2>/dev/null || { [ "$maj" -eq 6 ] && [ "$min" -ge 8 ]; } 2>/dev/null
    then r="OK"; else r="FAIL"; fi
  printf "  %-24s maj=%-6s min=%-8s -> %s\n" "$kver" "$maj" "$min" "$r"
}
echo "=== doc version logic, edge cases ==="
t 6.18.44-fc-v24
t 7.0.12-linuxkit
t 6.8.0-generic
t 6.7.9-generic
t 5.15.0-generic
t 6.12
t "6"
t "6.1.0-rpi"
t "4.19.0"
