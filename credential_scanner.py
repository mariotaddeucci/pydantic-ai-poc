"""Credential scanner — CLI entry point.

Delegates to credential_scanner.cli typer app.
"""
from credential_scanner.cli import app

if __name__ == "__main__":
    app()
