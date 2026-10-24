#!/usr/bin/env python3
"""DO NOT MERGE: supervises one diagnostic guest boot over QMP.

QEMU runs with its test terminal on a socket chardev (server, wait) and QMP on a socket,
both of which this connects to. It copies the terminal to TERMINAL_LOG. Each line that the
guest prints with the pause marker stops the VM and resumes it; in between, --pause decides:

- registers: saves every vCPU's registers ("info registers" reads them from KVM, which
  marks the vCPU dirty, so QEMU writes them back before it runs again: kvm_cpu_exec, QEMU
  v10.2.0 accel/kvm/kvm-all.c:2913-2931, 3171-3176);
- plain: nothing.

When the guest resets (QEMU runs with -action reboot=shutdown,shutdown=pause, so a triple
fault pauses the VM) or shuts down otherwise, it records the reason and quits QEMU.
"""

import argparse
import enum
import json
import logging
import select
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

PAUSE_MARKER = b"diag: pause"
CONNECT_DEADLINE_SECONDS = 60.0
CONNECT_RETRY_SECONDS = 0.1


class SupervisorError(Exception):
    pass


class Pause(enum.Enum):
    REGISTERS = "registers"
    PLAIN = "plain"


def connect_unix(path: Path) -> socket.socket:
    """Connects to QEMU's socket at path once QEMU has created it."""
    deadline = time.monotonic() + CONNECT_DEADLINE_SECONDS
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(path))
            return sock
        except (FileNotFoundError, ConnectionRefusedError) as err:
            sock.close()
            if time.monotonic() > deadline:
                raise SupervisorError(f"no QEMU socket at {path}") from err
            time.sleep(CONNECT_RETRY_SECONDS)


@dataclass
class Qmp:
    sock: socket.socket
    buffer: bytes = b""
    events: list[dict] = field(default_factory=list)

    def read_message(self) -> dict:
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise SupervisorError("QMP closed")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def execute(self, command: str, arguments: dict | None = None) -> object:
        request: dict = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.sock.sendall(json.dumps(request).encode() + b"\n")
        while True:
            message = self.read_message()
            match message:
                case {"return": value}:
                    return value
                case {"error": error}:
                    raise SupervisorError(f"QMP {command}: {error}")
                case {"event": _}:
                    self.events.append(message)
                case _:
                    raise SupervisorError(f"QMP {command}: unexpected {message}")

    def human(self, command_line: str) -> str:
        output = self.execute("human-monitor-command", {"command-line": command_line})
        if not isinstance(output, str):
            raise SupervisorError(f"HMP {command_line}: unexpected {output!r}")
        return output


def pause(qmp: Qmp, mode: Pause, count: int, out: Path) -> None:
    """Stops the VM at the guest's pause number count and resumes it, per mode."""
    qmp.execute("stop")
    logger.info("pause %d: stopped", count)
    match mode:
        case Pause.REGISTERS:
            (out / f"registers-{count}.txt").write_text(qmp.human("info registers -a"))
            logger.info("pause %d: saved the registers", count)
        case Pause.PLAIN:
            pass
    qmp.execute("cont")
    logger.info("pause %d: resumed", count)


def supervise(
    terminal: socket.socket,
    qmp: Qmp,
    terminal_log: Path,
    out: Path,
    mode: Pause,
) -> None:
    pauses = 0
    line = b""
    with terminal_log.open("ab") as log:
        while True:
            for event in qmp.events:
                if handle_event(event, qmp, out):
                    return
            qmp.events.clear()
            # select() does not see messages that an earlier read left in the buffer.
            if b"\n" in qmp.buffer:
                qmp.events.append(qmp.read_message())
                continue

            readable, _, _ = select.select([terminal, qmp.sock], [], [])
            if qmp.sock in readable:
                qmp.events.append(qmp.read_message())
            if terminal not in readable:
                continue

            chunk = terminal.recv(65536)
            if not chunk:
                return
            log.write(chunk)
            log.flush()
            # Whole lines, so that each marker counts once however the terminal splits it.
            *lines, line = (line + chunk).split(b"\n")
            for complete in lines:
                if PAUSE_MARKER in complete:
                    pauses += 1
                    pause(qmp, mode, pauses, out)


def handle_event(event: dict, qmp: Qmp, out: Path) -> bool:
    """Handles one QMP event; true when the boot is over."""
    match event:
        case {"event": "SHUTDOWN", "data": {"reason": reason}}:
            (out / "shutdown-reason.txt").write_text(reason + "\n")
            logger.info("shutdown: %s", reason)
            qmp.execute("quit")
            return True
        case {"event": _}:
            logger.debug("QMP event %s", event)
            return False
        case _:
            raise SupervisorError(f"QMP: unexpected {event}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--terminal-socket", type=Path, required=True)
    parser.add_argument("--qmp-socket", type=Path, required=True)
    parser.add_argument("--terminal-log", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="directory for the registers")
    parser.add_argument("--pause", type=Pause, choices=list(Pause), required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="ci-diag-qmp: %(message)s")

    terminal = connect_unix(args.terminal_socket)
    qmp = Qmp(connect_unix(args.qmp_socket))
    greeting = qmp.read_message()
    if "QMP" not in greeting:
        raise SupervisorError(f"QMP greeting: {greeting}")
    qmp.execute("qmp_capabilities")
    try:
        supervise(terminal, qmp, args.terminal_log, args.out, args.pause)
    finally:
        terminal.close()
        qmp.sock.close()


if __name__ == "__main__":
    main()
