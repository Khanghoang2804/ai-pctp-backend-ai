import asyncio
from app.core.database import querydb_dicts

async def main():
    rows = querydb_dicts("SELECT label, count(*) as count FROM pctp_nodes GROUP BY label", ())
    print(rows)

import sys
sys.path.append("/home/nemo/code/ast")
import app.core.database
# We need to run it synchronously or whatever querydb_dicts supports.
# Wait, querydb_dicts is synchronous? Let's check queryNodeAndRel.py to see if it awaits.
