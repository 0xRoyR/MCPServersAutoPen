"""
Initialize the SQLite database with all required tables.

Run this script to create the database file and tables:
    python init_db.py
    python init_db.py --force  # Force recreate all tables (drops existing data)
"""

import sys
from database.manager import DatabaseManager
from database.schema import SCHEMA


def main():
    print("Initializing database...")

    force = "--force" in sys.argv

    if force:
        print("Force recreate mode - dropping existing tables...")

    db = DatabaseManager()
    db.initialize(force_recreate=force)

    print(f"Database location: {db.db_path}")
    print(f"Creating {len(SCHEMA)} tables...")

    for table_name, table_info in SCHEMA.items():
        print(f"  - {table_name}: {table_info['description']}")

    print("\nDatabase initialized successfully!")

    # Show statistics
    stats = db.get_statistics()
    print("\nTable row counts:")
    for table, count in stats.items():
        print(f"  - {table}: {count} rows")


if __name__ == "__main__":
    main()
