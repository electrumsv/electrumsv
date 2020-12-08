try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.7.8 builds and version of 3.31.1.
    import sqlite3 # type: ignore
import time
from typing import Any, List, Optional, Sequence, Tuple, Type, TypeVar

from .sqlite_support import SQLITE_MAX_VARS


T = TypeVar('T')


# TODO(nocheckin) this should go away as the TxData structure goes away
# def apply_flags(data: TxData, flags: TxFlags) -> TxFlags:
#     flags &= ~TxFlags.METADATA_FIELD_MASK
#     if data.height is not None:
#         flags |= TxFlags.HasHeight
#     if data.fee is not None:
#         flags |= TxFlags.HasFee
#     if data.position is not None:
#         flags |= TxFlags.HasPosition
#     return flags


def collect_results(result_type: Type[T], cursor: sqlite3.Cursor, results: List[T]) -> None:
    """
    Collect the results of a query and extend a result list with correct typing.
    """
    rows = cursor.fetchall()
    cursor.close()
    results.extend(result_type(*row) for row in rows)


def flag_clause(column: str, flags: Optional[T], mask: Optional[T]) -> Tuple[str, List[T]]:
    if flags is None:
        if mask is None:
            return "", []
        return f"({column} & ?) != 0", [mask]

    if mask is None:
        return f"({column} & ?) != 0", [flags]

    return f"({column} & ?) == ?", [mask, flags]


def get_timestamp() -> int:
    return int(time.time())


def read_rows_by_id(return_type: Type[T], db: sqlite3.Connection, sql: str, params: List[Any], \
        ids: Sequence[int]) -> List[T]:
    """
    Batch read rows as constrained by database limitations.
    """
    results = []
    batch_size = SQLITE_MAX_VARS - len(params)
    while len(ids):
        batch_ids = ids[:batch_size]
        query = sql.format(",".join("?" for k in batch_ids))
        cursor = db.execute(query, params + batch_ids) # type: ignore
        rows = cursor.fetchall()
        cursor.close()
        results.extend(rows)
        ids = ids[batch_size:]
    return [ return_type(*t) for t in results ]


def update_rows_by_id(id_type: Type[T], db: sqlite3.Connection, sql: str, params: List[Any], \
        ids: Sequence[T]) -> int:
    """
    Batch update rows as constrained by database limitations.
    """
    batch_size = SQLITE_MAX_VARS - len(params)
    rows_updated = 0
    while len(ids):
        batch_ids = ids[:batch_size]
        query = sql.format(",".join("?" for k in batch_ids))
        cursor = db.execute(query, params + batch_ids) # type: ignore
        rows_updated += cursor.rowcount
        cursor.close()
        ids = ids[batch_size:]
    return rows_updated

