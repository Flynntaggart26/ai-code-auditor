import os, subprocess, hashlib, pickle
API_KEY = "sk-live-supersecret12345"
PASSWORD = "admin123"

def run_user(cmd):
    return os.system("ls " + cmd)

def query(conn, user_id):
    return conn.execute(f"SELECT * FROM users WHERE id={user_id}")

def load(data):
    return pickle.loads(data)

def weak(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def deep(x):
    if x:
        for i in range(5):
            while x > 1:
                if i:
                    for j in range(3):
                        if j:
                            try:
                                eval(str(x))
                            except:
                                pass
    return x
