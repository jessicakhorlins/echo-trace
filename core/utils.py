import re


def detect_xss2(user_input):
    xss_pattern = re.compile(
        r"<(script|img|svg|iframe|a|div|etc)\b[^>]*>.*?</\1>", re.IGNORECASE
    )
    if xss_pattern.search(user_input):
        return True
    return False


def detect_xss(payload):
    xss_patterns = [
        r"<\s*script[^>]*>.*?<\s*/\s*script\s*>",
        r'<\s*img[^>]*\s+onerror\s*=\s*["\'].*?["\']\s*>',
        r'<\s*a[^>]*\s+href\s*=\s*["\']javascript:.*?["\'].*?>',
        r'<\s*svg[^>]*\s+onload\s*=\s*["\'].*?["\']\s*>',
        r'<\s*iframe[^>]*\s+src\s*=\s*["\']javascript:.*?["\']\s*>',
        r'<\s*img[^>]*\s+onload\s*=\s*["\'].*?["\']\s*>',
        r'<\s*script[^>]*\s+src\s*=\s*["\']http://attacker\.com/malicious\.js["\']\s*>',
        r'<\s*a[^>]*\s+href\s*=\s*["\']data:text/html,.*?["\'].*?>',
        r'<\s*img[^>]*\s+onmouseover\s*=\s*["\'].*?["\']\s*>',
        r'<\s*video[^>]*>\s*<\s*source[^>]*\s+onerror\s*=\s*["\'].*?["\']\s*>\s*</\s*video\s*>',
        r"<script.*?>.*?<\/script>",
        r"<img.*?src=.*?onerror=.*?>",
        r"<a.*?href=.*?javascript:.*?>",
        r"<iframe.*?src=.*?onload=.*?>",
        r"<div.*?style=.*?expression\(.*?\)",
    ]

    if any(re.search(pattern, payload, re.IGNORECASE) for pattern in xss_patterns):
        return True

    elif detect_xss2(payload):
        return True
    return False


def detect_sql_injection2(user_input):
    # Define a list of common SQL injection keywords and patterns
    sql_injection_keywords = [
        "SELECT",
        "UPDATE",
        "DELETE",
        "INSERT",
        "DROP",
        "UNION",
        "OR",
        "1=1",
    ]

    user_input = user_input.upper()
    for keyword in sql_injection_keywords:
        if keyword in user_input:
            return True
    return False


def detect_sql_injection(request):
    sql_injection_patterns = [
        r"['\"]\s*OR\s+.*?['\"]",
        r"['\"]\s*UNION\s+.*?SELECT\s+.*?['\"]",
        r"['\"]\s*AND\s+.*?['\"]",
        r"['\"]\s*DROP\s+TABLE\s+.*?['\"]",
        r"['\"]\s*INSERT\s+INTO\s+.*?['\"]",
        r"['\"]\s*DELETE\s+FROM\s+.*?['\"]",
        r"['\"]\s*EXEC\s+.*?['\"]",
        r"['\"]\s*DECLARE\s+.*?['\"]",
        r"['\"]\s*XP_CMDSHELL\s+.*?['\"]",
    ]

    if any(
        re.search(pattern, request, re.IGNORECASE) for pattern in sql_injection_patterns
    ):
        return True

    elif detect_sql_injection2(request):
        return True

    else:
        sql_injection_pattern = r"['\"]\s*(?:OR|UNION|AND|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|EXEC|DECLARE|XP_CMDSHELL)\s+.*?['\"]"

        if re.search(sql_injection_pattern, request, re.IGNORECASE):
            return True
    return False


request_counts = {}


def detect_dos(source_ip, destination_ip, threshold=50):
    key = (source_ip, destination_ip)

    if key not in request_counts:
        request_counts[key] = 1
    else:
        request_counts[key] += 1

    if request_counts[key] > threshold:
        return True

    return False


login_attempts = {}


def detect_brute_force(request, max_attempts=5):
    if "username=" in request and "password=" in request:
        username = re.search(r"username=(.*?)&", request).group(1)
        password = re.search(r"password=(.*?)$", request).group(1)

        user_key = username
        if user_key not in login_attempts:
            login_attempts[user_key] = {"attempts": 1, "status": "failed"}
        else:
            login_attempts[user_key]["attempts"] += 1

        if login_attempts[user_key]["attempts"] > max_attempts:
            login_attempts[user_key]["status"] = "locked"

        return login_attempts[user_key]["status"] == "locked"

    return False
