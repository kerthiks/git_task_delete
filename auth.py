# auth.py

def login(user):
    if user["role"] == "kerthik":
        return "User logged in"
    else:
        raise Exception("Only regular users can log in")  # ❌ Bug: excludes admin
