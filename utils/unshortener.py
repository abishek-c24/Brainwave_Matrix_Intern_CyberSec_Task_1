import requests

def unshorten_url(url):
    try:
        session = requests.Session()
        session.max_redirects = 5  # limit to avoid infinite loops
        response = session.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        return final_url
    except requests.exceptions.RequestException:
        return "[ERROR] Failed to unshorten"
