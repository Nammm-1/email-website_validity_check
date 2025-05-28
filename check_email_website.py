import re
import requests
import dns.resolver
import smtplib
import random
import socket
from difflib import get_close_matches

# Email format regex
EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"

# List of known disposable email domains (partial, for demo)
DISPOSABLE_DOMAINS = set([
    'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com',
    'tempmail.com', 'yopmail.com', 'getnada.com', 'dispostable.com',
    'fakeinbox.com', 'maildrop.cc', 'mintemail.com', 'throwawaymail.com',
    'sharklasers.com', 'spamgourmet.com', 'mailnesia.com', 'mailcatch.com',
])

# List of popular email domains for typo detection
POPULAR_DOMAINS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
    'aol.com', 'protonmail.com', 'zoho.com', 'gmx.com', 'mail.com',
]

# Common fake username patterns
FAKE_USERNAMES = [
    'test', 'fake', 'no-reply', 'noreply', 'example', 'admin', 'user', 'sample', 'demo', 'temp', 'null', 'none', 'email', 'contact', 'info', 'abc', 'asdf', 'qwerty'
]

# For gibberish detection, a simple heuristic: long, random-looking usernames
GIBBERISH_THRESHOLD = 8  # length
GIBBERISH_CONSONANTS = set('bcdfghjklmnpqrstvwxyz')

def is_valid_email_format(email):
    return re.match(EMAIL_REGEX, email) is not None


def is_disposable_email(domain, username):
    # 1. Check against static list
    if domain.lower() in DISPOSABLE_DOMAINS:
        return True, 'static-list'
    # 2. Check with API (open.kickbox.com)
    try:
        resp = requests.get(f'https://open.kickbox.com/v1/disposable/{domain}', timeout=3)
        if resp.status_code == 200 and resp.json().get('disposable'):
            return True, 'kickbox-api'
    except Exception:
        pass
    return False, None


def detect_domain_typo(domain):
    matches = get_close_matches(domain, POPULAR_DOMAINS, n=1, cutoff=0.8)
    if matches:
        return matches[0]
    return None


def is_gibberish_username(username):
    # Heuristic: long, mostly consonants, not in fake patterns
    if len(username) >= GIBBERISH_THRESHOLD:
        consonant_count = sum(1 for c in username.lower() if c in GIBBERISH_CONSONANTS)
        if consonant_count / len(username) > 0.7:
            return True
    return False


def is_fake_pattern_username(username):
    uname = username.lower()
    for pattern in FAKE_USERNAMES:
        if uname == pattern or uname.startswith(pattern) or uname.endswith(pattern):
            return True, pattern
    return False, None


def has_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [r.exchange.to_text() for r in answers]
    except Exception:
        return []


def has_a_or_aaaa_record(domain):
    try:
        a = dns.resolver.resolve(domain, 'A')
        if a:
            return True
    except Exception:
        pass
    try:
        aaaa = dns.resolver.resolve(domain, 'AAAA')
        if aaaa:
            return True
    except Exception:
        pass
    return False


def smtp_check(email, mx_hosts):
    for mx in mx_hosts:
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx)
            server.helo()
            # Try VRFY
            try:
                code, msg = server.verify(email)
                if code == 250:
                    server.quit()
                    return True, f"VRFY: {msg.decode()}"
            except Exception:
                pass
            # Try EXPN (for mailing lists)
            try:
                code, msg = server.expn(email)
                if code == 250:
                    server.quit()
                    return True, f"EXPN: {msg.decode()}"
            except Exception:
                pass
            # Fallback to RCPT TO
            server.mail('test@example.com')
            code, message = server.rcpt(email)
            server.quit()
            if code == 250 or code == 251:
                return True, f"SMTP server {mx} accepted RCPT TO."
            else:
                return False, f"SMTP server {mx} rejected RCPT TO: {code} {message.decode()}"
        except Exception as e:
            continue
    return False, "Could not verify email via SMTP (all MX servers failed or rejected)."


def is_catch_all(domain, mx_hosts):
    random_user = f"catchalltest{random.randint(100000,999999)}"
    test_email = f"{random_user}@{domain}"
    for mx in mx_hosts:
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx)
            server.helo()
            server.mail('test@example.com')
            code, message = server.rcpt(test_email)
            server.quit()
            if code == 250 or code == 251:
                return True
        except Exception:
            continue
    return False


def is_valid_url_format(url):
    return re.match(r"^https?://[\w\.-]+", url) is not None


def website_status(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        status = response.status_code
        final_url = response.url
        if response.history:
            redirects = [resp.status_code for resp in response.history]
            return status, final_url, redirects
        else:
            return status, final_url, []
    except Exception as e:
        return None, None, str(e)


def main():
    email = input("Enter an email address: ").strip()
    website = input("Enter a website URL (include http:// or https://): ").strip()

    print("\nChecking email...")
    email_valid = True
    smtp_inconclusive = False
    if not is_valid_email_format(email):
        print(f"Invalid email format: {email}")
        email_valid = False
    else:
        username, domain = email.split('@', 1)
        print(f"Domain: {domain}")
        # 1. Disposable check (static + API)
        is_disposable, method = is_disposable_email(domain, username)
        if is_disposable:
            if method == 'kickbox-api':
                print(f"Warning: {domain} is a disposable/temporary email provider (detected by Kickbox API).")
            else:
                print(f"Warning: {domain} is a known disposable/temporary email provider.")
            email_valid = False
        else:
            print(f"{domain} is not a known disposable email provider.")
        # 2. Typo detection for domain
        typo_suggestion = detect_domain_typo(domain)
        if typo_suggestion and typo_suggestion != domain:
            print(f"Warning: Did you mean '{username}@{typo_suggestion}'? (Possible typo in domain)")
            email_valid = False
        # 3. Gibberish username detection
        if is_gibberish_username(username):
            print(f"Warning: The username '{username}' looks like gibberish or random text.")
            email_valid = False
        # 4. Fake pattern username detection
        is_fake, pattern = is_fake_pattern_username(username)
        if is_fake:
            print(f"Warning: The username '{username}' matches a common fake pattern ('{pattern}').")
            email_valid = False
        # 5. Domain existence
        if has_a_or_aaaa_record(domain):
            print(f"Domain {domain} resolves to an IP address (A/AAAA record found).")
        else:
            print(f"Domain {domain} does NOT resolve to an IP address (no A/AAAA record found).")
            email_valid = False
        # 6. MX record
        mx_hosts = has_mx_record(domain)
        if mx_hosts:
            print(f"Email domain has MX record(s): {', '.join(mx_hosts)}")
            # 7. Catch-all detection
            if is_catch_all(domain, mx_hosts):
                print(f"Catch-all detected: {domain} accepts mail for any address.")
                email_valid = False
            else:
                print(f"No catch-all detected: {domain} does not accept mail for random addresses.")
            # 8. SMTP check (with VRFY/EXPN/RCPT)
            smtp_valid, smtp_msg = smtp_check(email, mx_hosts)
            if smtp_valid:
                print(f"SMTP check: DELIVERABLE ({smtp_msg})")
            else:
                print(f"SMTP check: NOT DELIVERABLE ({smtp_msg})")
                smtp_msg_lower = smtp_msg.lower()
                if (
                    'block' in smtp_msg_lower or
                    'spamhaus' in smtp_msg_lower or
                    'greylist' in smtp_msg_lower or
                    'temporar' in smtp_msg_lower or
                    'timeout' in smtp_msg_lower or
                    'connection' in smtp_msg_lower or
                    'unavailable' in smtp_msg_lower or
                    'try again' in smtp_msg_lower
                ):
                    print("Warning: SMTP check was inconclusive due to blocklist, connection, or temporary error. Cannot determine deliverability.")
                    smtp_inconclusive = True
                else:
                    email_valid = False
        else:
            print(f"Email domain does NOT have MX record: {domain}")
            email_valid = False
    # Final feedback
    if email_valid:
        print("\nEmail is VALID\n")
    elif smtp_inconclusive:
        print("\nEmail validity is INCONCLUSIVE due to mail server restrictions.\n")
    else:
        print("\nEmail is NOT VALID\n")

    print("\nChecking website...")
    if not is_valid_url_format(website):
        print(f"Invalid website URL format: {website}")
    else:
        status, final_url, redirects = website_status(website)
        if status is not None:
            print(f"HTTP status code: {status}")
            if redirects:
                print(f"Redirect chain: {' -> '.join(map(str, redirects))} -> {status}")
                print(f"Final URL after redirects: {final_url}")
            else:
                print(f"No redirects. URL reached: {final_url}")
            if 200 <= status < 400:
                print(f"Website is reachable: {final_url}")
            else:
                print(f"Website returned error status: {status}")
        else:
            print(f"Website is NOT reachable. Error: {redirects}")


if __name__ == "__main__":
    main() 