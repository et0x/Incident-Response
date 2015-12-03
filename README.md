# Incident-Response

### Get Names of All Services / Processes: 
#### (you can explicitly supply credentials with -Credentials)
```powershell
Get-AllProcesses -Computername @("192.168.1.1","DC1")
Get-AllServices -Computername @("192.168.1.1","DC1")
```

### Get Strings, optionally filter down to interesting items:
```powershell
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -NetworkItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -FileItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -RegistryItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -EmailItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -FunctionItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings

PS C:\users\et0x\desktop> Get-ChildItem -Recurse -path 'C:\users\et0x\Downloads\Prac MW Analysis\Practical Malware Analysis Labs\BinaryCollection\*' | Get-Content -raw | Get-Strings -RegistryItems
HKEY_CLASSES_ROOT
HKEY_CURRENT_CONFIG
HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE
HKEY_USERS
SYSTEM\CurrentControlSet\Services\
SYSTEM\CurrentControlSet\Services\%s\Parameters\
SYSTEM\CurrentControlSet\Control\DeviceClasses
SYSTEM\CurrentControlSet\Services\
HKEY_CLASSES_ROOT
HKEY_CURRENT_CONFIG
HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE
HKEY_USERS
SYSTEM\CurrentControlSet\Services\
SYSTEM\CurrentControlSet\Services\%s\Parameters\
```
### Differential Analysis of Running Processes via Hashing: 
#### (optionally supply creds)
```powershell
Invoke-ProcessHashSweep -ComputerNames @("192.168.1.1","DC1") -SupplyCreds
```

### Differential Analysis of Installed Services via Hashing: 
#### (optionally supply creds)
```powershell
PS C:\users\et0x\desktop> Invoke-ServiceHashSweep -ComputerNames @("192.168.197.162","192.168.197.163","IE10Win7") -SupplyCreds

Name                           Value                                                                              
----                           -----                                                                              
192.168.197.162                2D-AE-B9-6C-D5-AB-0B-63-F2-2E-F9-F9-2E-DF-69-EC   
192.168.197.163                2D-AE-B9-6C-D5-AB-0B-63-F2-2E-F9-F9-2E-DF-69-EC
IE10Win7                       D4-1D-8C-D9-8F-00-B2-04-E9-80-09-98-EC-F8-42-7E
```

## More to come!
