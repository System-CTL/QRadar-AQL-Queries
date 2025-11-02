# TA0006-T1558-Potential Kerberos Request from Outside
*Source*: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771

You can track all 4771 events where the Client Address is not from your internal IP range or not from private IP ranges.

```
and when the event(s) were detected by one or more of Microsoft Windows Security Event Log
and when the event matches Event ID is any of [4771 or 4768 or 4769]
and NOT when the event matches Source IP is any of [10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16 or 169.254.0.0/16 or 224.0.0.0/4]
```
