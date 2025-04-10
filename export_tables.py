import os
import psycopg2
import json
import datetime
import csv

# Get database connection details from environment variables
db_url = os.environ.get('DATABASE_URL')
if not db_url:
    print("ERROR: DATABASE_URL environment variable not found.")
    exit(1)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
export_dir = f"database_export_{timestamp}"
os.makedirs(export_dir, exist_ok=True)

try:
    # Connect to the database
    print(f"Connecting to database...")
    conn = psycopg2.connect(db_url)
    cursor = conn.cursor()
    
    # Get list of tables
    cursor.execute("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
    """)
    tables = [table[0] for table in cursor.fetchall()]
    
    print(f"Found {len(tables)} tables: {', '.join(tables)}")
    
    # Export table structure
    schema_file = os.path.join(export_dir, "schema.sql")
    with open(schema_file, 'w') as f:
        for table in tables:
            cursor.execute(f"""
                SELECT 
                    'CREATE TABLE ' || table_name || ' (' ||
                    string_agg(column_name || ' ' || data_type || 
                        CASE WHEN character_maximum_length IS NOT NULL 
                            THEN '(' || character_maximum_length || ')' 
                            ELSE '' END || 
                        CASE WHEN is_nullable = 'NO' 
                            THEN ' NOT NULL' 
                            ELSE '' END,
                        ', ' ORDER BY ordinal_position) || ');'
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
                GROUP BY table_name
            """, (table,))
            
            create_table_stmt = cursor.fetchone()[0]
            f.write(f"{create_table_stmt}\n\n")
    
    # Export data from each table
    for table in tables:
        print(f"Exporting data from {table}...")
        output_file = os.path.join(export_dir, f"{table}.csv")
        
        cursor.execute(f"SELECT * FROM {table}")
        columns = [desc[0] for desc in cursor.description]
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(columns)  # Write header
            for row in cursor:
                writer.writerow(row)  # Write data rows
    
    # Create a summary JSON file
    summary = {
        "timestamp": timestamp,
        "tables": tables,
        "row_counts": {}
    }
    
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        summary["row_counts"][table] = count
    
    with open(os.path.join(export_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Create a ZIP file of the export
    import shutil
    zip_file = f"{export_dir}.zip"
    shutil.make_archive(export_dir, 'zip', export_dir)
    
    print(f"Database export completed successfully!")
    print(f"Export directory: {export_dir}")
    print(f"ZIP file: {zip_file}")
    print(f"You can download the ZIP file from the Replit Files panel.")
    
    # Print file sizes
    zip_size = os.path.getsize(zip_file)
    print(f"ZIP file size: {zip_size / 1024:.2f} KB")
    
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    if 'conn' in locals():
        conn.close()