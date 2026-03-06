#sanitizer.py
def sanitize_xss(value):
    """
    Simulates HTML escaping to prevent XSS
    """
    value = value.replace("<", "&lt;")
    value = value.replace(">", "&gt;")
    value = value.replace("&", "&amp;")
    return value


def sanitize_sql(value):
    """
    Simulates SQL escaping to prevent SQL Injection
    """
    value = value.replace("'", "''")
    value = value.replace("--", "")
    return value

