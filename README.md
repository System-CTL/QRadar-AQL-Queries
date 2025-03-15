# QRadar-AQLQueries
 Useful AQL Queries

 ## 1. Living-of-the-Land Binaries
 ```sql
 Select sourceip, destinationip, "Process Name" FROM events WHERE "Process Name" IMATCHES '.*atbroker\.exe.*|.*bash\.exe.*|.*bitsadmin\.exe.*|.*certutil\.exe.*|.*cmdkey\.exe.*|.*cmstp\.exe.*|.*control\.exe.*|.*csc\.exe.*|.*cscript\.exe.*|.*dfsvc\.exe.*|.*diskshadow\.exe.*|.*dnscmd\.exe.*|.*esentutl\.exe.*|.*eventvwr\.exe.*|.*expand\.exe.*|.*extexport\.exe.*|.*extrac32\.exe.*|.*findstr\.exe.*|.*forfiles\.exe.*|.*ftp\.exe.*|.*gpscript\.exe.*|.*hh\.exe.*|.*ie4uinit\.exe.*|.*ieexec\.exe.*|.*infdefaultinstall\.exe.*|.*installutil\.exe.*|.*makecab\.exe.*|.*reg\.exe.*|.*print\.exe.*|.*presentationhost\.exe.*|.*pcwrun\.exe.*|.*pcalua\.exe.*|.*odbcconf\.exe.*|.*msiexec\.exe.*|.*mshta\.exe.*|.*msdt\.exe.*|.*msconfig\.exe.*|.*msbuild\.exe.*|.*mmc\.exe.*|.*microsoft.workflow.compiler\.exe.*|.*mavinject\.exe.*|.*vsjitdebugger\.exe.*|.*tracker\.exe.*|.*te\.exe.*|.*sqltoolsps\.exe.*|.*sqlps\.exe.*|.*sqldumper\.exe.*|.*rcsi\.exe.*|.*msxsl\.exe.*|.*msdeploy\.exe.*|.*mftrace\.exe.*|.*dxcap\.exe.*|.*dnx\.exe.*|.*csi\.exe.*|.*cdb\.exe.*|.*bginfo\.exe.*|.*appvlp\.exe.*|.*xwizard\.exe.*|.*wsreset\.exe.*|.*wscript\.exe.*|.*wmic\.exe.*|.*wab\.exe.*|.*verclsid\.exe.*|.*syncappvpublishingserver\.exe.*|.*scriptrunner\.exe.*|.*schtasks\.exe.*|.*sc\.exe.*|.*runscripthelper\.exe.*|.*runonce\.exe.*|.*rundll32\.exe.*|.*rpcping\.exe.*|.*replace\.exe.*|.*regsvr32\.exe.*|.*regsvcs\.exe.*|.*register-cimprovider\.exe.*|.*regedit\.exe.*|.*regasm\.exe.*|' GROUP BY "Process Name",sourceip LAST 3 DAYS
```
## 2. RDP over a reverse SSH Tunnel
Source MENASEC Blog

```sql
select sourceip, sourceport, destinationip, destinationport from events where eventid=5156 and (sourceport=3389 or destinationport=3389) and (INCIDR('127.0.0.0/8',sourceip) OR INCIDR('127.0.0.0/8',destinationip)) GROUP BY sourceip LAST 24 HOURS
```

## 3. Spawning Windows Shell
Source : SIGMA Rules
```sql
SELECT UTF8(payload) as search_payload from events where (((LOGSOURCETYPENAME(devicetype) ilike 'Microsoft Windows Security Event Log')) and (("EventID"='4688' and (search_payload ilike '%\cmd.exe' or search_payload ilike '%\powershell.exe' or search_payload ilike '%\wscript.exe' or search_payload ilike '%\cscript.exe'or search_payload ilike '%\sh.exe' or search_payload ilike '%\bash.exe' or search_payload ilike '%\scrcons.exe' or search_payload ilike '%\schtasks.exe' or search_payload ilike '%\regsvr32.exe' or search_payload ilike '%\mshta.exe' or search_payload ilike '%\rundll32.exe' or search_payload ilike '%\msiexec.exe')))) GROUP BY sourceip LAST 3 DAYS
```

## 4. Potential DNS Tunneling 
Source : N/A
```sql
SELECT LOGSOURCENAME(logsourceid),sourceip, destinationip, "<dns_url_query_field_name>","DNS Error Code",STRLEN("<dns_url_query_field_name>") FROM events WHERE (LOGSOURCETYPENAME(devicetype)) ILIKE '%<DNS_logsource>%' AND STRLEN("<dns_url_query_field_name>")>250 AND NOT INCIDR('192.X.X.0/20',sourceip) AND "<dns_url_query_field_name>" IS NOT NULL AND "<dns_url_query_field_name>" NOT ILIKE '%<excluded_url_1>%' AND "<dns_url_query_field_name>" NOT ILIKE '%<excluded_url_2>%' START PARSEDATETIME('8 day ago')
```

## 5. Explicit Credential - Windows 
Source : N/A
```sql
SELECT DATEFORMAT(devicetime,'yyyy-MM-dd hh:mm') AS "TimeStamp",LOGSOURCENAME(logsourceid) AS "LogSource Name",QIDNAME(qid) As "Event Name" ,"Process Name",sourceip AS "Source IP",sourceport AS "Source Port",destinationip AS "Destination IP",destinationport AS "Destination Port",username AS "Username","Account Name" AS "Account Name" FROM events WHERE (LOGSOURCETYPENAME(devicetype)) ILIKE '%Microsoft Windows%' AND qidEventId=4648 AND username!="Account Name" AND username NOT LIKE '%$' AND "Account Name" NOT LIKE '%$' AND username!='-' AND "Account Name"!='-' AND username IS NOT NULL AND "Account Name" IS NOT NULL AND username NOT IN ('1st_username_exclusion') AND username NOT IN ('2nd_username_exclusion') START PARSEDATETIME('1 day ago')
```

## 6. Inbound RDP Connection - Firewall
Source : N/A
```sql
SELECT DATEFORMAT(devicetime,'yyyy-MM-dd hh:mm') AS "TimeStamp",LOGSOURCENAME(logsourceid) AS "LogSource Name",QIDNAME(qid) As "Event Name" ,"Logon Process" AS "Logon Process","Process Name",sourceip AS "Source IP",sourceport AS "Source Port",destinationip AS "Destination IP",destinationport AS "Destination Port",username AS "Username","Account Name" AS "Account Name", "Logon Type" AS "Logon Type" ,qideventid AS "Event ID"  FROM events WHERE (LOGSOURCETYPENAME(deviceType) ILIKE '%Firewall_Type_Name_1%' OR LOGSOURCETYPENAME(deviceType) ILIKE '%Firewall_Type_Name_2%')  AND  NOT (sourceIP BETWEEN '10.0.0.0' AND '10.255.255.255') AND NOT (sourceIP BETWEEN '172.16.0.0' AND '172.31.255.255') AND NOT ( destinationip BETWEEN '192.168.0.0' AND '192.168.255.255') AND destinationport=3389  START PARSEDATETIME('20 days ago')
```

## 7. Outbound RDP Connection - Firewall
Source : N/A
```sql
SELECT DATEFORMAT(devicetime,'yyyy-MM-dd hh:mm') AS "TimeStamp",LOGSOURCENAME(logsourceid) AS "LogSource Name",QIDNAME(qid) As "Event Name" ,"Logon Process" AS "Logon Process","Process Name",destinationip AS "Source IP",sourceport AS "Source Port",destinationip AS "Destination IP",destinationport AS "Destination Port",username AS "Username","Account Name" AS "Account Name", "Logon Type" AS "Logon Type" ,qideventid AS "Event ID"  FROM events WHERE (LOGSOURCETYPENAME(deviceType) ILIKE '%Firewall_Type_Name_1%' OR LOGSOURCETYPENAME(deviceType) ILIKE '%Firewall_Type_Name_2%')  AND  NOT (destinationip BETWEEN '10.0.0.0' AND '10.255.255.255') AND NOT (destinationip BETWEEN '172.16.0.0' AND '172.31.255.255') AND NOT ( destinationip BETWEEN '192.168.0.0' AND '192.168.255.255') AND destinationport=3389  START PARSEDATETIME('20 days ago')
```
