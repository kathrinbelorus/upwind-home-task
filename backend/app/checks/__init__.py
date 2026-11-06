"""Detection checks.

Each check is a module with a `run(email: ParsedEmail) -> list[Finding]` function.
To add a check, write a new module and register it in ALL_CHECKS.
"""

from app.checks import attachments, authentication, content, links, sender

ALL_CHECKS = [authentication, sender, links, content, attachments]
