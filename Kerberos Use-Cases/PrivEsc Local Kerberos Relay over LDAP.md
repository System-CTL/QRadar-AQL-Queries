# TA0004-T1548-PrivEsc Local Kerberos Relay over LDAP

*Source*: https://detection.fyi/sigmahq/sigma/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap/

Detects a suspicious local successful logon event where the Logon Package is Kerberos, the remote address is set to localhost, and the target user SID is the built-in local Administrator account.
    This may indicate an attempt to leverage a Kerberos relay attack variant that can be used to elevate privilege locally from a domain joined limited user to local System privileges.    
```
and when the event(s) were detected by one or more of Microsoft Windows Security Event Log
and when the event matches Event ID is any of 4624
and when the event matches Logon Type is any of 3
and when the event matches Source IP is 127.0.0.1
and when the event matches Logon Process contains any of Kerberos
and when the event matches Target Account Security ID contains any of [admin or Admin or ADMIN or Administrator or -500]
```

<img width="565" height="705" alt="image" src="https://github.com/user-attachments/assets/e007f359-ef7b-46a2-992a-f7a2ffa2b05c" />
