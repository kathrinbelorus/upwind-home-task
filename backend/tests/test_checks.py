from app.analyzer import analyze_email
from app.models import Attachment, EmailIn

GMAIL_PASS = "mx.google.com; dkim=pass header.i=@paypal.com; spf=pass; dmarc=pass"
GMAIL_FAIL = "mx.google.com; dkim=fail; spf=fail smtp.mailfrom=evil.ru; dmarc=fail"


def checks_hit(result) -> set[str]:
    return {f.title for f in result.findings}


def test_benign_email_is_safe():
    result = analyze_email(EmailIn(
        sender="LeetCode <no-reply@leetcode.com>",
        subject="LeetCode Weekly Digest",
        authentication_results="mx.google.com; dkim=pass; spf=pass; dmarc=pass",
        body_html='<p>Your weekly problems: <a href="https://leetcode.com/problems">leetcode.com</a></p>',
    ))
    assert result.verdict == "Safe"
    assert result.score == 0


def test_classic_phishing_is_malicious():
    result = analyze_email(EmailIn(
        sender="PayPal Security <alert@paypa1-secure.ru>",
        reply_to="support@collector.xyz",
        subject="Urgent: your account will be suspended",
        authentication_results=GMAIL_FAIL,
        body_html='<a href="http://45.33.12.9/login">www.paypal.com/login</a> verify your account',
    ))
    assert result.verdict == "Malicious"
    assert result.score == 100
    hits = checks_hit(result)
    assert "Possible PayPal impersonation" in hits
    assert "Link text hides the real destination" in hits
    assert "Link to a raw IP address" in hits
    assert "DMARC fail" in hits


def test_forged_auth_header_is_not_trusted():
    result = analyze_email(EmailIn(
        sender="a@b.com",
        authentication_results="evil.example; spf=pass; dkim=pass; dmarc=pass",
    ))
    assert "Untrusted authentication results" in checks_hit(result)


def test_dkim_passes_if_any_signature_passes():
    result = analyze_email(EmailIn(
        sender="a@b.com",
        authentication_results="mx.google.com; dkim=fail; dkim=pass; spf=pass; dmarc=pass",
    ))
    assert result.findings == []


def test_display_name_with_other_address():
    result = analyze_email(EmailIn(
        sender='"support@bank.com" <x@attacker.net>',
        authentication_results=GMAIL_PASS,
    ))
    assert "Display name shows a different address" in checks_hit(result)


def test_subdomains_of_same_site_are_not_flagged():
    result = analyze_email(EmailIn(
        sender="News <news@mail.example.co.uk>",
        authentication_results=GMAIL_PASS,
        body_html='<a href="https://www.example.co.uk/a">example.co.uk</a>',
    ))
    assert result.findings == []


def test_risky_attachments():
    result = analyze_email(EmailIn(
        sender="a@b.com",
        authentication_results=GMAIL_PASS,
        attachments=[
            Attachment(filename="invoice.pdf.exe"),
            Attachment(filename="report.docm"),
            Attachment(filename="photo_‮gpj.exe"),
            Attachment(filename="notes.pdf"),
        ],
    ))
    hits = checks_hit(result)
    assert {"Disguised executable attachment", "Office file with macros",
            "Attachment name hides its real type"} <= hits
    # The hidden character must not reach the displayed text.
    assert all("‮" not in f.detail for f in result.findings)


def test_script_and_punycode_links():
    result = analyze_email(EmailIn(
        sender="a@b.com",
        authentication_results=GMAIL_PASS,
        body_html='<a href="javascript:alert(1)">x</a><a href="https://xn--pypal-4ve.com">y</a>',
    ))
    assert {"Script link", "Look-alike domain"} <= checks_hit(result)


def test_hebrew_urgency():
    result = analyze_email(EmailIn(
        sender="a@b.com",
        authentication_results=GMAIL_PASS,
        body_text="פעולה נדרשת: החשבון שלך ייחסם, אמת את החשבון",
    ))
    assert {"Pressure or urgency language", "Asks for credentials or payment details"} <= checks_hit(result)


def test_script_tag_content_is_ignored():
    result = analyze_email(EmailIn(
        sender="a@b.com",
        authentication_results=GMAIL_PASS,
        body_html="<script>urgent verify your account</script><p>hello</p>",
    ))
    assert result.findings == []
