"""Credential scanner — backwards-compatible entry point.

Delegates to credential_scanner.pipeline.
"""

import asyncio

from credential_scanner.pipeline import main

if __name__ == "__main__":
    asyncio.run(main())
