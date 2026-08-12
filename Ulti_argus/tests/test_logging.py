from __future__ import annotations

import json
import logging

from argus_v.oracle_core.logging import _FallbackJsonFormatter


def test_dependency_free_json_formatter_contract() -> None:
    formatter = _FallbackJsonFormatter(
        "%(levelname)s %(name)s %(message)s",
        rename_fields={"levelname": "level", "name": "logger"},
    )
    record = logging.LogRecord(
        name="argus.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=12,
        msg="capture unavailable",
        args=(),
        exc_info=None,
    )
    record.fields = {"interface": "eth0"}

    result = json.loads(formatter.format(record))

    assert result == {
        "level": "WARNING",
        "logger": "argus.test",
        "message": "capture unavailable",
        "fields": {"interface": "eth0"},
    }
