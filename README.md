# Incident-Response

## Examples:

### Get Names of All Services: (you can explicitly supply credentials with -Credentials)
Get-AllProcesses -Computername @("192.168.1.1","DC1")
Get-AllServices -Computername @("192.168.1.1","DC1")

### Get Strings, optionally filter down to interesting items:
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -NetworkItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -FileItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -RegistryItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -EmailItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings -Length 5 -FunctionItems
Get-Content -Raw -Path c:\evil.exe | Get-Strings

### Differential Analysis of Running Processes via Hashing: (optionally supply creds)
Invoke-ProcessHashSweep -ComputerNames @("192.168.1.1","DC1") -SupplyCreds

### Differential Analysis of Installed Services via Hashing: (optionally supply creds)
Invoke-ProcessHashSweep -ComputerNames @("192.168.1.1","DC1") -SupplyCreds


## More to come!
