def detect_phishing(email):
    score = 0
    reasons = []

    email_lower = email.lower()

    # Rule 1: Urgency / Threat
    urgent_words = ["urgent", "immediately", "24 hours", "suspended", "limited"]
    for word in urgent_words:
        if word in email_lower:
            score += 1
            reasons.append("Uses urgent or threatening language")
            break

    # Rule 2: Sensitive info request
    sensitive_words = ["password", "verify your account", "confirm your information", "otp"]
    for word in sensitive_words:
        if word in email_lower:
            score += 1
            reasons.append("Requests sensitive information")
            break

    # Rule 3: Suspicious links
    if "http://" in email or "bit.ly" in email or "tinyurl" in email:
        score += 1
        reasons.append("Contains suspicious or shortened links")

    # Rule 4: Generic greeting
    if "dear customer" in email_lower or "dear user" in email_lower:
        score += 1
        reasons.append("Uses generic greeting")

    # Classification
    if score >= 3:
        return "Phishing ⚠️", reasons
    elif score == 2:
        return "Suspicious ⚠️", reasons
    else:
        return "Safe ✅", reasons


# ---- RUN PROGRAM ----
if __name__ == "__main__":
    print("=== Phishing Email Detector ===\n")
    email = input("Paste email content:\n")

    result, reasons = detect_phishing(email)

    print("\nResult:", result)
    print("\nReasons:")
    for r in reasons:
        print("-", r)

    print("\nAdvice:")
    print("- Do NOT click suspicious links")
    print("- Do NOT share credentials")
    print("- Verify sender before responding")
