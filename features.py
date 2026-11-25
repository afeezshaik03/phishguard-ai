import re
from urllib.parse import urlparse

def extract_features(url):
    url = str(url)
    features = {}

    # Basic counts
    features["url_length"]      = len(url)
    features["count_dots"]      = url.count(".")
    features["count_hyphens"]   = url.count("-")
    features["count_slash"]     = url.count("/")
    features["count_question"]  = url.count("?")
    features["count_equal"]     = url.count("=")
    features["count_at"]        = url.count("@")
    features["count_digits"]    = sum(c.isdigit() for c in url)
    features["count_special"]   = len(re.findall(r'[^a-zA-Z0-9]', url))

    # Security flags
    features["has_https"]       = 1 if url.startswith("https") else 0
    features["has_ip"]          = 1 if re.search(
                                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                                    url) else 0
    features["has_at_symbol"]   = 1 if "@" in url else 0
    features["double_slash"]    = 1 if "//" in url[8:] else 0

    # Suspicious keywords
    sus = ["secure","login","verify","update","bank",
           "account","password","confirm","free","lucky"]
    features["has_sus_word"]    = 1 if any(
                                    w in url.lower() for w in sus) else 0

    # Domain features
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        features["domain_length"]    = len(domain)
        features["count_subdomains"] = max(domain.count(".") - 1, 0)
        features["path_length"]      = len(parsed.path)
        features["has_port"]         = 1 if ":" in domain else 0
        features["query_length"]     = len(parsed.query)
    except:
        features["domain_length"]    = 0
        features["count_subdomains"] = 0
        features["path_length"]      = 0
        features["has_port"]         = 0
        features["query_length"]     = 0

    # Ratio features
    features["digit_ratio"]   = features["count_digits"] / max(len(url),1)
    features["special_ratio"] = features["count_special"] / max(len(url),1)

    return features
