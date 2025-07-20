import pyodbc
import os
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

load_dotenv()
bcrypt = Bcrypt()

#ไฟล์นี้มีไว้ใช้เพื่อเพิ่่มข้อมูล User เข้า Database เพราะระบบไม่มี Register

conn_str = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    f"SERVER={os.getenv('DB_SERVER')};"
    f"DATABASE={os.getenv('DB_DATABASE')};"
    f"UID={os.getenv('DB_UID')};"
    f"PWD={os.getenv('DB_PWD')};"
)
conn = pyodbc.connect(conn_str)

def add_user(username, password, role):
    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Users (username, password, role) VALUES (?, ?, ?)",
        username, hashed, role
    )
    conn.commit()
    print(f"User '{username}' added.")

if __name__ == "__main__":
    add_user("admin", "admin123456", "admin")
    add_user("user", "user123456", "user")