# TA0006-T1558-Potential Kerberos Request from Outside
*Source*: https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_susp_kerberos_manipulation/

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771

Detects failed Kerberos TGT issue operation. This can be a sign of manipulations of TGT messages by an attacker.

Expected False Positive: - Faulty legacy applications, also i have removed the 0x10 code which triggered false positives.
```
and when the event(s) were detected by one or more of Microsoft Windows Security Event Log
and when the event matches Event ID is any of [4771 or 4768 or 4769]
and when the event matches Error Code (custom) is any of [0x9 or 0xA or 0xB or 0xF or 0x11 or 0x13 or 0x14 or 0x1A or 0x1F or 0x21 or 0x22 or 0x23 or 0x24 or 0x26 or 0x27 or 0x28 or 0x29 or 0x2C or 0x2D or 0x2E or 0x2F or 0x31 or 0x32 or 0x3E or 0x3F or 0x40 or 0x41 or 0x43 or 0x44]
and when at least 2 events are seen with the same Source IP in 1 minutes
```
