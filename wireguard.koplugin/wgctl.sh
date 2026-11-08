#!/bin/sh
# Process control for wireproxy, called by the KOReader plugin.
# Kept POSIX/busybox-ash compatible: PocketBook firmware ships busybox.
#
#   wgctl.sh start <binary> <config> <pidfile> <logfile> <watch_pid> <info_addr> [verbose]
#   wgctl.sh stop <pidfile>
#   wgctl.sh status <pidfile>
#
# Exit codes: 0 ok / running, 1 not running, 2 bad config, 3 died on start,
# 4 missing binary or config, 64 usage.

is_running() {
    [ -f "$1" ] || return 1
    pid=$(cat "$1" 2>/dev/null)
    [ -n "$pid" ] || return 1
    [ -d "/proc/$pid" ] || return 1
    # Guard against a recycled PID belonging to some other process.
    tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -q wireproxy
}

do_stop() {
    pidfile=$1
    if ! is_running "$pidfile"; then
        rm -f "$pidfile"
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null
    i=0
    while [ $i -lt 20 ] && [ -d "/proc/$pid" ]; do
        sleep 0.1 2>/dev/null || sleep 1
        i=$((i + 1))
    done
    [ -d "/proc/$pid" ] && kill -KILL "$pid" 2>/dev/null
    rm -f "$pidfile"
    return 0
}

do_start() {
    bin=$1 conf=$2 pidfile=$3 log=$4 watch=$5 info=$6 verbose=$7

    if is_running "$pidfile"; then
        return 0
    fi
    if [ ! -f "$bin" ] || [ ! -f "$conf" ]; then
        echo "missing binary ($bin) or config ($conf)" >"$log"
        return 4
    fi
    [ -x "$bin" ] || chmod +x "$bin" 2>/dev/null

    if ! "$bin" -n -c "$conf" >"$log" 2>&1; then
        return 2
    fi

    if [ "$verbose" = "1" ]; then
        "$bin" -c "$conf" -i "$info" >"$log" 2>&1 </dev/null &
    else
        "$bin" -s -c "$conf" -i "$info" >"$log" 2>&1 </dev/null &
    fi
    pid=$!
    echo "$pid" >"$pidfile"

    # Watchdog: stop the tunnel once KOReader exits (or crashes), so it
    # never outlives the app. Only removes the pidfile if it is still ours.
    (
        while kill -0 "$watch" 2>/dev/null && kill -0 "$pid" 2>/dev/null; do
            sleep 15
        done
        kill -TERM "$pid" 2>/dev/null
        [ "$(cat "$pidfile" 2>/dev/null)" = "$pid" ] && rm -f "$pidfile"
    ) </dev/null >/dev/null 2>&1 &

    # wireproxy exits immediately on bind errors etc.; give it a moment.
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$pidfile"
        return 3
    fi
    return 0
}

cmd=$1
[ $# -gt 0 ] && shift
case "$cmd" in
    start)
        [ $# -ge 6 ] || exit 64
        do_start "$@"
        ;;
    stop)
        [ $# -ge 1 ] || exit 64
        do_stop "$1"
        ;;
    status)
        [ $# -ge 1 ] || exit 64
        is_running "$1"
        ;;
    *)
        echo "usage: $0 start|stop|status ..." >&2
        exit 64
        ;;
esac
