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

