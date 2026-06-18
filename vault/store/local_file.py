from __future__ import annotations
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from vault.crypto import KeyWrapper, seal_token, open_token
from vault.model import Connection, ConnKey, ConnectionGrant, ConnectionAccessLog, Token
from vault.store.base import Store


class LocalFileStore(Store):
    def __init__(self, root: Path, wrapper: KeyWrapper):
        self.root = Path(root)
        self.wrapper = wrapper

    def _dir(self, key: ConnKey) -> Path:
        return self.root / "connections" / key.org / key.provider

    def _rec_path(self, key: ConnKey) -> Path:
        return self._dir(key) / f"{key.account}.json"

    def _tok_path(self, key: ConnKey) -> Path:
        return self._dir(key) / f"{key.account}.token.age"

    def _lock_path(self, key: ConnKey) -> Path:
        return self._dir(key) / f"{key.account}.lock"

    def _write_sealed(self, key: ConnKey, token: Token) -> None:
        p = self._tok_path(key)
        tmp = p.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, seal_token(token, self.wrapper))
        finally:
            os.close(fd)
        os.replace(str(tmp), str(p))  # atomic on POSIX; readers never see a truncated file

    def put_connection(self, conn: Connection) -> None:
        self._dir(conn.key).mkdir(parents=True, exist_ok=True)
        self._rec_path(conn.key).write_text(json.dumps(conn.to_record()))
        if conn.token is not None:
            self._write_sealed(conn.key, conn.token)

    def get_connection(self, key: ConnKey) -> Optional[Connection]:
        rp = self._rec_path(key)
        if not rp.exists():
            return None
        rec = json.loads(rp.read_text())
        token = None
        if self._tok_path(key).exists():
            token = open_token(self._tok_path(key).read_bytes(), self.wrapper)
        return Connection.from_record(rec, token=token)

    def list_connections(self, org: str, provider: Optional[str]) -> list[Connection]:
        base = self.root / "connections" / org
        out = []
        if not base.exists():
            return out
        for prov_dir in base.iterdir():
            if provider is not None and prov_dir.name != provider:
                continue
            for rec in prov_dir.glob("*.json"):
                acct = rec.stem
                out.append(self.get_connection(ConnKey(org, prov_dir.name, acct)))
        return out

    def write_token(self, key: ConnKey, token: Token, now: float) -> None:
        self._write_sealed(key, token)
        rp = self._rec_path(key)
        rec = json.loads(rp.read_text())
        rec["updated_at"] = now
        tmp = rp.with_suffix(".tmp")
        tmp.write_text(json.dumps(rec))
        os.replace(str(tmp), str(rp))  # atomic on POSIX

    def acquire_lease(self, key: ConnKey, holder: str, until: float, now: float) -> bool:
        self._dir(key).mkdir(parents=True, exist_ok=True)
        p = self._lock_path(key)
        try:
            fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"{holder}\n{until}".encode())
            os.close(fd)
            return True
        except FileExistsError:
            try:
                cur_until = float(p.read_text().split("\n", 1)[1])
            except (OSError, IndexError, ValueError):
                cur_until = 0.0
            if cur_until > now:
                return False
            # expired — steal by overwriting
            p.write_text(f"{holder}\n{until}")
            return True

    def release_lease(self, key: ConnKey, holder: str) -> None:
        p = self._lock_path(key)
        try:
            if p.exists() and p.read_text().split("\n", 1)[0] == holder:
                p.unlink()
        except OSError:
            pass

    def lease_held(self, key: ConnKey, now: float) -> bool:
        p = self._lock_path(key)
        if not p.exists():
            return False
        try:
            return float(p.read_text().split("\n", 1)[1]) > now
        except (OSError, IndexError, ValueError):
            return False

    def delete_connection(self, key: ConnKey) -> None:
        tok = self._tok_path(key)
        if tok.exists():
            size = tok.stat().st_size
            with open(tok, "wb") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
            tok.unlink()
        for p in (self._rec_path(key), self._lock_path(key)):
            if p.exists():
                p.unlink()

    def _jsonl(self, sub: str, cid: str) -> Path:
        return self.root / sub / f"{cid}.jsonl"

    def add_grant(self, grant: ConnectionGrant) -> None:
        p = self._jsonl("grants", grant.connection_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(asdict(grant)) + "\n")

    def get_grants(self, connection_id: str) -> list[ConnectionGrant]:
        p = self._jsonl("grants", connection_id)
        if not p.exists():
            return []
        return [ConnectionGrant(**json.loads(line)) for line in p.read_text().splitlines() if line]

    def append_log(self, entry: ConnectionAccessLog) -> None:
        p = self._jsonl("logs", entry.connection_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def read_log(self, connection_id: str) -> list[ConnectionAccessLog]:
        p = self._jsonl("logs", connection_id)
        if not p.exists():
            return []
        return [ConnectionAccessLog(**json.loads(line)) for line in p.read_text().splitlines() if line]
