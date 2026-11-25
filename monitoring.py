"""Read Linux host metrics without blocking for a sampling interval."""
import shutil
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from threading import Lock

_lock = Lock()
_last_cpu = None
PERIODS = {"1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000}
RETENTION = PERIODS["30d"]


def proc(name):
    try:
        return (Path("/proc") / name).read_text(encoding="ascii").splitlines()
    except OSError:
        return []


def cpu_counters():
    lines = proc("stat")
    if not lines:
        return None, None
    counters = [int(value) for value in lines[0].split()[1:9]]
    return sum(counters), counters[3] + counters[4]


def cpu_percent(current, previous):
    total, idle = current
    if (previous and total is not None and previous[0] is not None
            and total > previous[0] and idle >= previous[1]):
        return max(0, min(100, round(100 * (1 - (idle - previous[1]) / (total - previous[0])))))
    return None


def cpu_usage():
    global _last_cpu
    counters = cpu_counters()
    with _lock:
        previous, _last_cpu = _last_cpu, counters
    return cpu_percent(counters, previous)


def host_metrics(storage, sample_cpu=True):
    memory = {line.split(":")[0]: int(line.split()[1]) for line in proc("meminfo")}
    uptime = proc("uptime")
    traffic = [line.replace(":", " ").split() for line in proc("net/dev")[2:]]
    interfaces = [row for row in traffic if row[0] != "lo"]
    try:
        disk = shutil.disk_usage(storage)
    except OSError:
        disk = None
    return {
        "cpu": cpu_usage() if sample_cpu else None,
        "ram": round(100 * (1 - memory["MemAvailable"] / memory["MemTotal"]))
        if memory.get("MemTotal") and "MemAvailable" in memory else None,
        "disk": disk.free if disk else None,
        "uptime": int(float(uptime[0].split()[0])) if uptime else None,
        "traffic": (sum(int(row[1]) for row in interfaces), sum(int(row[9]) for row in interfaces))
        if traffic else None,
    }


def collect_sample(storage, now=None):
    now = int(time.time()) if now is None else now
    metrics = host_metrics(storage, sample_cpu=False)
    total, idle = cpu_counters()
    rx, tx = metrics["traffic"] or (None, None)
    uptime = metrics["uptime"]
    with closing(sqlite3.connect(storage / "monitoring.sqlite3")) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS samples (
            at INTEGER PRIMARY KEY, cpu INTEGER, ram INTEGER, disk INTEGER,
            rx_rate REAL, tx_rate REAL, uptime INTEGER, total INTEGER, idle INTEGER, rx INTEGER, tx INTEGER
        )""")
        db.execute("BEGIN IMMEDIATE")
        previous = db.execute("SELECT at, uptime, total, idle, rx, tx FROM samples WHERE at < ? ORDER BY at DESC LIMIT 1",
                              (now,)).fetchone()
        cpu = rx_rate = tx_rate = None
        if previous and uptime is not None and previous[1] is not None:
            interval = now - previous[0]
            if 0 < interval <= 180 and abs(uptime - previous[1] - interval) <= 5:
                cpu = cpu_percent((total, idle), previous[2:4])

                def rate(value, prior):
                    return (value - prior) / interval if value is not None and prior is not None and value >= prior else None

                rx_rate, tx_rate = rate(rx, previous[4]), rate(tx, previous[5])
        db.execute("INSERT OR REPLACE INTO samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (now, cpu, metrics["ram"], metrics["disk"], rx_rate, tx_rate, uptime, total, idle, rx, tx))
        db.execute("DELETE FROM samples WHERE at < ?", (now - RETENTION,))


def history(storage, period, now=None):
    now = int(time.time()) if now is None else now
    duration = PERIODS[period]
    start, step = now - duration, max(60, (duration + 239) // 240)
    source = storage / "monitoring.sqlite3"
    if not source.is_file():
        return []
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as db:
        return db.execute("""SELECT min(at), avg(cpu), avg(ram), avg(disk), avg(rx_rate), avg(tx_rate)
            FROM samples WHERE at BETWEEN ? AND ? GROUP BY (at - ?) / ? ORDER BY min(at)""",
                          (start, now, start, step)).fetchall()
