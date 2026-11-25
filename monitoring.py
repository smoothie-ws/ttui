"""Read Linux host metrics without blocking for a sampling interval."""
import shutil
from pathlib import Path
from threading import Lock

_lock = Lock()
_last_cpu = None


def proc(name):
    try:
        return (Path("/proc") / name).read_text(encoding="ascii").splitlines()
    except OSError:
        return []


def cpu_usage():
    global _last_cpu
    lines = proc("stat")
    if not lines:
        return None
    counters = [int(value) for value in lines[0].split()[1:9]]
    total, idle = sum(counters), counters[3] + counters[4]
    with _lock:
        previous, _last_cpu = _last_cpu, (total, idle)
        if previous and total > previous[0] and idle >= previous[1]:
            return round(100 * (1 - (idle - previous[1]) / (total - previous[0])))
    return None


def host_metrics(storage):
    memory = {line.split(":")[0]: int(line.split()[1]) for line in proc("meminfo")}
    uptime = proc("uptime")
    traffic = [line.replace(":", " ").split() for line in proc("net/dev")[2:]]
    interfaces = [row for row in traffic if row[0] != "lo"]
    try:
        disk = shutil.disk_usage(storage)
    except OSError:
        disk = None
    return {
        "cpu": cpu_usage(),
        "ram": round(100 * (1 - memory["MemAvailable"] / memory["MemTotal"]))
        if memory.get("MemTotal") and "MemAvailable" in memory else None,
        "disk": disk.free if disk else None,
        "uptime": int(float(uptime[0].split()[0])) if uptime else None,
        "traffic": (sum(int(row[1]) for row in interfaces), sum(int(row[9]) for row in interfaces))
        if traffic else None,
    }
