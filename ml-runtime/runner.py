"""ML Runtime task runner — picks up task.json, writes task_status.json and findings.json."""

import json
import time
from pathlib import Path

IPC_DIR = Path("/data/ipc")

def main():
    """Poll for new tasks and execute them."""
    print("ml-runtime runner.py: waiting for tasks...")
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
    """Process a single task."""
    task_data = json.loads((task_dir / "task.json").read_text())
    status_file = task_dir / "task_status.json"
    findings_file = task_dir / "findings.json"

    # Write running status
    status_file.write_text(json.dumps({
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "progress": 0,
    }))

    # Stub execution
    time.sleep(1)

    # Write completion
    findings_file.write_text(json.dumps([]))
    status_file.write_text(json.dumps({
        "status": "done",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "progress": 100,
    }))


if __name__ == "__main__":
    main()
