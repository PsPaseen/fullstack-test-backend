import jwt, os, pyodbc, datetime
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_cors import CORS


app = Flask(__name__)
app.config['SECRET_KEY'] = 'fullteamtech-test'
bcrypt = Bcrypt(app)
load_dotenv()
CORS(app)

#เก็บ blacklist
blacklist_refresh_tokens = set()

# เชื่อมต่อ MS SQL Server
connnect_db = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    f"SERVER={os.getenv('DB_SERVER')};"
    f"DATABASE={os.getenv('DB_DATABASE')};"
    f"UID={os.getenv('DB_UID')};"
    f"PWD={os.getenv('DB_PWD')};"
)
conn = pyodbc.connect(connnect_db)

def find_user(username):
    conn = pyodbc.connect(connnect_db)  # สร้าง connection ใหม่ทุกครั้ง
    cursor = conn.cursor()
    cursor.execute("SELECT username, password, role FROM Users WHERE username = ?", username)
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if row:
        return {"username": row.username, "password": row.password, "role": row.role}
    return None

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = find_user(data.get("username"))
    if not user or not bcrypt.check_password_hash(user["password"], data.get("password")):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = jwt.encode({
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    refresh_token = jwt.encode({
        "username": user["username"],
        "type": "refresh",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        "accessToken": access_token,
        "refreshToken": refresh_token
    }), 200

@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.json
    refresh_token = data.get("refreshToken")
    if not refresh_token:
        return jsonify({"error": "Missing refresh token"}), 400
    
    if refresh_token in blacklist_refresh_tokens:
        return jsonify({"error": "Refresh token revoked"}), 401

    try:
        payload = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        # ตรวจสอบว่าเป็น refresh token จริง
        if payload.get("type") != "refresh":
            return jsonify({"error": "Invalid token type"}), 401

        user = find_user(payload.get("username"))
        if not user:
            return jsonify({"error": "User not found"}), 404

        access_token = jwt.encode({
            "username": user["username"],
            "role": user["role"],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({"accessToken": access_token}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401
    
@app.route('/logout', methods=['POST'])
def logout():
    data = request.json
    refresh_token = data.get("refreshToken")
    if refresh_token:
        blacklist_refresh_tokens.add(refresh_token)
    return jsonify({"message": "Logged out. Token blacklisted."}), 200

@app.route('/me', methods=['POST'])
def me():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    access_token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user = find_user(payload.get("username"))
        if not user:
            return jsonify({"error": "User not found"}), 404
        # คืนข้อมูลผู้ใช้ (ไม่คืน password)
        return jsonify({
            "username": user["username"],
            "role": user["role"]
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid access token"}), 401
    
@app.route('/menus', methods=['POST'])
def menus():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    access_token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        role = payload.get("role")
        if not role:
            return jsonify({"error": "Role not found"}), 403


        # กำหนดเมนูตามสิทธิ์
        menus = []
        if role == "admin":
            menus = [
            {"name": "หน้าแรก", "path": "/", "visible": True},
            {"name": "รายงาน", "path": "/report", "visible": True},
            {"name": "จัดการสิทธิ์", "path": "/manage-roles", "visible": True},
            {"name": "ออกจากระบบ", "path": "/logout", "visible": True}
        ]
        elif role == "user":
             menus = [
            {"name": "หน้าแรก", "path": "/", "visible": True},
            {"name": "รายงาน", "path": "/report", "visible": True},
            {"name": "จัดการสิทธิ์", "path": "/manage-roles", "visible": False},
            {"name": "ออกจากระบบ", "path": "/logout", "visible": True}
        ]
             
        return jsonify({"menus": menus}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid access token"}), 401
    
# extra เสริมเข้ามาครับ เพราะว่าถ้าเราเช็ค role จาก localstorage มันจะไม่ปลอดภัย เพราะดปลี่ยนกันได้ เลยเช็คจาก jwt เฟี้ยวกว่าครับ
@app.route('/manage-page', methods=['POST'])
def manage_page():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    access_token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        role = payload.get("role")
        if role != "admin":
            return jsonify({"allow": False, "role": role}), 200

        # อนุมัติให้เข้าหน้า ManagePage ได้
        return jsonify({"allow": True, "role": role}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid access token"}), 401

if __name__ == '__main__':
    app.run(port=4000)