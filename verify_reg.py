import urllib.request
import urllib.parse
import time
import sys

BASE_URL = "http://127.0.0.1:5000"

def register(username, password):
    url = f"{BASE_URL}/register"
    data = urllib.parse.urlencode({'username': username, 'password': password}).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    
    try:
        with urllib.request.urlopen(req) as response:
            # If successful (redirect), checking URL or code might be tricky with urlopen handling redirects
            # urlopen automatically follows redirects.
            # So if we are redirected to login (/), the final URL will be /.
            return response.geturl(), response.read().decode()
    except urllib.error.HTTPError as e:
        return e.url, e.read().decode()

def test():
    # Allow server to start
    print("Waiting for server...")
    time.sleep(3)
    
    # 1. Register a new user
    user = f"user_{int(time.time())}"
    print(f"Registering new user: {user}")
    url, content = register(user, "password")
    
    if url.endswith("/dashboard") or url.endswith("/"): # Redirects to / on success (which is login page)
        print("PASS: Registration successful (redirected).")
    else:
        print(f"FAIL: Registration failed. URL: {url}")
        sys.exit(1)

    # 2. Register same user again
    print(f"Registering duplicate user: {user}")
    
    # Preventing auto-redirect to check the response page content
    # urllib follows redirects by default. We can use a custom opener or just check if we stayed on /register page (which happens if we render_template)
    # When render_template is used, the URL stays /register.
    
    url, content = register(user, "password")
    
    if url.endswith("/register"):
        print("PASS: Stayed on register page.")
        if "Username already registered" in content:
            print("PASS: Error message found.")
        else:
            print("FAIL: Error message NOT found.")
            print(content)
            sys.exit(1)
    else:
        print(f"FAIL: Redirected unexpectedly to {url}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        test()
        print("All tests passed!")
    except Exception as e:
        print(f"An error occurred: {e}")
        # sys.exit(1) 
