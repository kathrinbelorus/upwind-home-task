"""Risky attachments, judged by file name only (contents are never opened)."""

from app.models import Finding
from app.parsing import ParsedEmail
from app.utils import clean_for_display

NAME = "attachments"

EXECUTABLE = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "msi", "ps1", "jar", "lnk", "reg", "cpl", "dll",
}
MACRO_OFFICE = {"docm", "xlsm", "pptm", "dotm", "xlam"}
# Disk images are used to slip executables past Windows' "downloaded file" warnings.
DISK_IMAGE = {"iso", "img", "vhd", "vhdx"}
DOCUMENT_LOOKING = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}

RTL_OVERRIDE = "‮"  # can make "invoice_fdp.exe" render as "invoice_exe.pdf"


def _extensions(filename: str) -> list[str]:
    parts = filename.lower().strip().rstrip(".").split(".")
    return parts[1:] if len(parts) > 1 else []


def run(email: ParsedEmail) -> list[Finding]:
    findings = []

    for attachment in email.attachments:
        name = attachment.filename
        shown = clean_for_display(name)
        exts = _extensions(name)
        ext = exts[-1] if exts else ""

        if RTL_OVERRIDE in name:
            findings.append(Finding(
                check=NAME,
                title="Attachment name hides its real type",
                detail=f'"{shown}" uses a hidden character that reverses text to disguise its extension.',
                points=40,
            ))
        elif ext in EXECUTABLE and len(exts) >= 2 and exts[-2] in DOCUMENT_LOOKING:
            findings.append(Finding(
                check=NAME,
                title="Disguised executable attachment",
                detail=f'"{shown}" looks like a .{exts[-2]} file but is actually a .{ext} program.',
                points=40,
            ))
        elif ext in EXECUTABLE:
            findings.append(Finding(
                check=NAME,
                title="Executable attachment",
                detail=f'"{shown}" is a .{ext} file that can run code on your computer.',
                points=35,
            ))
        elif ext in MACRO_OFFICE:
            findings.append(Finding(
                check=NAME,
                title="Office file with macros",
                detail=f'"{shown}" can contain macros, a common way to deliver malware.',
                points=25,
            ))
        elif ext in DISK_IMAGE:
            findings.append(Finding(
                check=NAME,
                title="Disk image attachment",
                detail=f'"{shown}" is a disk image, often used to bypass security warnings.',
                points=25,
            ))

    return findings
