"""MySQL users table + salted hashing (no chat storage).""" 

#File imports
import pymysql
import os
import hmac
import hashlib

from dotenv import load_dotenv
load_dotenv()

DATABASE_CONFIGURATION = {"host": os.getenv("DB_HOST", "localhost"),
                          "port": int(os.getenv("DB_PORT", "3306")),
                          "user": os.getenv("DB_USER"),
                          "password": os.getenv("DB_PASS"),
                          "database": os.getenv("DB_NAME", "securechat"),
                          "cursorclass": pymysql.cursors.DictCursor,
                          "autocommit": True}


#Connecting to database
def connecting():
    return pymysql.connect(**DATABASE_CONFIGURATION)

#Initalizing databse
def init_db():
    sql = """
    CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(255) NOT NULL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL
    );
    """

    connection = connecting()
    with connection.cursor() as cursor:
        cursor.execute(sql)
    connecting.close()

#User registration
def create_user(email: str, username: str, salt: bytes, pwd_hash: str):
    connection = connecting()
    try:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                           (email, username, salt, pwd_hash))
        return True
    except pymysql.err.IntegrityError:
        return False
    finally:
        connection.close()

#User retrieval
def get_user_by_email(email: str):
    connection = connecting()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT email, username, salt, pwd_hash FROM users WHERE email = %s", (email,))
            return cursor.fetchone()
    finally:
        connection.close()

def get_user_by_username(username: str):
    connection = connecting()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT email, username, salt, pwd_hash FROM users WHERE username = %s", (username,))
            return cursor.fetchone()
    finally:
        connection.close()

#Password verification
def verify_password(stored_hash: str, salt_bytes: bytes, given_password: str):
    h = hashlib.sha256()
    h.update(salt_bytes + given_password.encode())
    return hmac.compare_digest(stored_hash, h.hexdigest())
