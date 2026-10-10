"""Get a CyberAccess API key without going through HTTP at all.

Useful on machines where local antivirus/network inspection interferes with
POST requests to localhost dev servers (see run_dev_server.py's history notes)
- this creates the tenant directly against the database instead of via
POST /v1/signup, so it's immune to that entirely.

Usage:
    python get_api_key.py "your-company-name"
    python get_api_key.py "your-company-name" you@company.com
"""
import sys

from app import _create_tenant_record

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python get_api_key.py <company-name> [email]")
        sys.exit(1)

    name = sys.argv[1]
    email = sys.argv[2] if len(sys.argv) > 2 else None
    result = _create_tenant_record(name, email)

    print()
    print("=" * 60)
    print("TENANT ID:", result["tenant_id"])
    print("API KEY:  ", result["api_key"])
    print("=" * 60)
    print(result["warning"])
