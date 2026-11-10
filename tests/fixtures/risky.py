import pickle
import subprocess


def run_user_command(command):
    return subprocess.run(command, shell=True, check=False)


def load_blob(blob):
    return pickle.loads(blob)


def build_query(cursor, user_id):
    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
