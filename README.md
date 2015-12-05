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

### Get WMI Filters, Consumers, Binding Paths, or All From Remote Machines
```powershell
PS C:\users\et0x> Get-WMIEventSubscriptions -Type All -ComputerNames @("192.168.197.153","IE10Win7") -Credentialed

Name                           Value                                                                                                                                                          
----                           -----                                                                                                                                                          
192.168.197.153                {\\IE10WIN72\ROOT\subscription:__FilterToConsumerBinding.Consumer="CommandLineEventConsumer.Name=\"DCI200\"",Filter="__EventFilter.Name=\"DCI200\"" \\IE10WI...
IE10Win7                       {\\IE10WIN7\ROOT\subscription:__FilterToConsumerBinding.Consumer="NTEventLogEventConsumer.Name=\"SCM Event Log Consumer\"",Filter="__EventFilter.Name=\"SCM ...

PS C:\users\et0x> Get-WMIEventSubscriptions -Type Filter -ComputerNames @("192.168.197.153","IE10Win7") -Credentialed -ShowDefinitions

Name                           Value                                                                                                                                                          
----                           -----                                                                                                                                                          
192.168.197.153                {__EventFilter.Name="DCI200", __EventFilter.Name="SCM Event Log Filter"}                                                                                       
IE10Win7                       {__EventFilter.Name="SCM Event Log Filter"} 


PS C:\users\et0x> Get-WMIEventSubscriptions -Type Consumer -ComputerNames @("192.168.197.153","IE10Win7") -Credentialed -ShowDefinitions
Name                           Value                                                                                                                                                          
----                           -----                                                                                                                                                          
192.168.197.153                {CommandLineEventConsumer.Name="DCI200", NTEventLogEventConsumer.Name="SCM Event Log Consumer"}                                                                
IE10Win7                       {NTEventLogEventConsumer.Name="SCM Event Log Consumer"}
```


###Get All Info From WMI Event Subscriptions on a list of Remote Machines
```powershell
PS C:\users\et0x> Invoke-EnumerateAllWMIEventSubscriptions -ComputerNames @("192.168.197.153","IE10Win7") -Credentialed

[+]  HOST: 192.168.197.153

Name                : DCI200
CommandLineTemplate : c:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -enc JAB3AHMAaABlAGwAbAAgAD0AIABuAGUAdwAtAG8AYgBqAGUAYwB0ACAALQBjAG8AbQBvAGIAagBlAGMAdAAgAFcAc
                      wBjAHIAaQBwAHQALgBzAGgAZQBsAGwAOwAkAHcAcwBoAGUAbABsAC4AUABvAHAAdQBwACgAIgBXAGUAIABoAGEAdgBlACAAYQAgAFcATQBJACAAYgBpAG4AZABpAG4AZwAgAC4ALgAuACIALAAgADAALAAgACIARABDAEkAM
                      gAwADAAIgAsACAAMAB4ADAAKQA=
ExecutablePath      : 
WorkingDirectory    : 

Name  : DCI200
Query : SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System" AND TargetInstance.SystemUpTime >= 240 AND 
        TargetInstance.SystemUpTime < 325

[+]  HOST: 192.168.197.153

Name      : SCM Event Log Consumer
EventID   : 0
EventType : 1
Category  : 0

Name  : SCM Event Log Filter
Query : select * from MSFT_SCMEventLogEvent

[+]  HOST: IE10Win7

Name      : SCM Event Log Consumer
EventID   : 0
EventType : 1
Category  : 0

Name  : SCM Event Log Filter
Query : select * from MSFT_SCMEventLogEvent
```

###Differential Analysis of WMI Event Subscription Hashes
```powershell
PS C:\users\et0x> Invoke-WMIHashSweep -ComputerNames @("192.168.197.153","IE10Win7") -Credentialed

Name                           Value                                                                                                                                                          
----                           -----                                                                                                                                                          
192.168.197.153                73-45-82-E1-5C-A9-66-65-CC-0D-A2-4E-69-E1-D7-6B                                                                                                                
IE10Win7                       3A-57-5A-26-91-14-61-CA-3A-A3-65-B4-17-1B-C7-7C
```

###More to come!