from fastapi import FastAPI
from views.vulnerability_view import router as vulnerability_router
import psycopg2
import uvicorn

db_config = {
    "dbname": "task_db",
    "user": "postgres",
    "password": "pass",
    "host": "localhost",
    "port": "5432"
}

app = FastAPI()

app.include_router(vulnerability_router)

@app.on_event("startup")
async def import_sql_file():
    """Runs SQL file when the app starts if the table does not exist."""
    try:
        connection = psycopg2.connect(**db_config)
        connection.autocommit = True
        cursor = connection.cursor()

        table_name = "vuln"  
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = %s
            );
        """, (table_name,))
        table_exists = cursor.fetchone()[0]

        if not table_exists:
            with open('app/vuln_data.sql', 'r') as file:
                sql_commands = file.read()

            cursor.execute(sql_commands)
            print("SQL file executed successfully.")
        else:
            print("Table already exists. Skipping SQL file execution.")
    except Exception as e:
        print(f"Error during SQL file execution: {str(e)}")
    finally:
        if connection:
            cursor.close()
            connection.close()



if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)