from __future__ import annotations

import jsonschema

from bus.model import EnvelopeError


class SchemaRegistry:
    """Maps a schema id+version (e.g. "voucher/v1") to a JSON Schema for `data`."""

    def __init__(self) -> None:
        self._schemas: dict[str, dict] = {}

    def register(self, schema_id: str, json_schema: dict) -> None:
        self._schemas[schema_id] = json_schema

    def validate_data(self, schema_id: str, data: dict) -> None:
        schema = self._schemas.get(schema_id)
        if schema is None:
            raise EnvelopeError(f"unknown data schema: {schema_id!r}")
        try:
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as exc:
            # path-only; never echo the offending value back to the caller
            path = "/".join(str(p) for p in exc.absolute_path) or "<root>"
            raise EnvelopeError(f"data does not match {schema_id} at {path}") from None
