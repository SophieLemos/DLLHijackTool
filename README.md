# DLLHijackTool

Small tool to detect pontencial DLL hijacking oppurtunities.

# What is DLL hijacking

Due to the DLL search order on Windows, we may be able to get a program to run our DLL, which can lead to privilege escalation or persistence.

# Usage

```
PS C:\> .\DLLHijackTool.exe
DLLHijackTool 1.0.0
Copyright (C) 2021 DLLHijackTool

ERROR(S):
  Required option 'u, user' is missing.

  -u, --user          Required. User to check for write privileges.

  -e, --executable    Test a single running executable.

  -p, --privilege     Check only processes running with this privilege.

  --help              Display this help screen.

  --version           Display version information.

```
