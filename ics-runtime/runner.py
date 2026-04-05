"""ICS Runtime task runner — mirrors ml-runtime protocol. Stub for M4."""

import json
import time
from pathlib import Path

IPC_DIR = Path("/data/ipc")

def main():
    print("ics-runtime runner.py: waiting for tasks...")
    while True:
        for task_dir in sorted(IPC_DIR.iterdir()) if IPC_DIR.exists() else []:
            if not task_dir.is_dir():
                continue
            task_file = task_dir / "task.json"
            status_file = task_dir / "task_status.json"
            if task_file.exists() and not status_file.exists():
                process_task(task_dir)
        time.sleep(2)


def process_task(task_dir: Path):
    task_data = json.loads((task_dir / "task.json").read_text())
    status_file = task_dir / "task_status.json"
    findings_file = task_dir / "findings.json"

    status_file.write_text(json.dumps({
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "progress": 0,
    }))

    time.sleep(1)

    findings_file.write_text(json.dumps([]))
    status_file.write_text(json.dumps({
        "status": "done",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "progress": 100,
    }))


if __name__ == "__main__":
    main()
