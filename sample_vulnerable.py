import os, subprocess, hashlib, pickle, random, tempfile, ssl
import telnetlib
API_KEY = "sk-live-supersecret12345"

def run_user(cmd):
    return os.system("ls " + cmd)

def tainted_demo():
    user = input("cmd: ")
    return os.system("ping " + user)

def query(conn, user_id):
    return conn.execute(f"SELECT * FROM users WHERE id={user_id}")

def load(data):
    return pickle.loads(data)

def weak(pw):
    import secrets
    assert len(pw) > 3
    return hashlib.md5(pw.encode()).hexdigest() + str(random.randint(0, 9))

def risky_net():
    t = telnetlib.Telnet("host", 23)
    ctx = ssl._create_unverified_context()
    f = tempfile.mktemp()
    return t, ctx, f
