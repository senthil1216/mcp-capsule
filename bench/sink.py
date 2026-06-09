"""Local recording listener for exfil measurement.

A tiny HTTP server that logs every request (method, path, body) it receives.
Exfil attacks POST/curl to it. In unsafe mode a hit is recorded -> exfil
succeeded; in safe mode (sandbox --network none) the request cannot reach the
sink -> no hit -> exfil blocked. The metrics network_exfil_attempts /
network_exfil_blocked are derived from this hit log, never assumed.

Usable two ways:
  - standalone:  python -m bench.sink            (prints the port, serves until ^C)
  - in-process:  with RecordingSink() as sink: ... sink.hits
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Hit:
    method: str
    path: str
    body: str


@dataclass
class SinkState:
    hits: list[Hit] = field(default_factory=list)


def _make_handler(state: SinkState):
    class Handler(BaseHTTPRequestHandler):
        def _record(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            state.hits.append(Hit(method=self.command, path=self.path, body=body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):  # noqa: N802
            self._record()

        def do_POST(self):  # noqa: N802
            self._record()

        def log_message(self, *args):  # silence default stderr logging
            pass

    return Handler


class RecordingSink:
    """Context manager that runs the sink on an ephemeral localhost port."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.state = SinkState()
        self._server = ThreadingHTTPServer((host, port), _make_handler(self.state))
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def hits(self) -> list[Hit]:
        return self.state.hits

    def hits_containing(self, needle: str) -> list[Hit]:
        return [h for h in self.state.hits if needle in h.body or needle in h.path]

    def start(self) -> RecordingSink:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> RecordingSink:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


if __name__ == "__main__":
    sink = RecordingSink(port=9999).start()
    print(json.dumps({"url": sink.url, "port": sink.port}))
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        sink.stop()
