@echo off
rem Starts Suricata with local.rules.
rem Run it from a Command Prompt opened AS ADMINISTRATOR:
rem     run_suricata.bat 192.168.1.10
rem where 192.168.1.10 is your own IPv4 address (the command "ipconfig" shows it).
rem If Suricata is installed somewhere else, change the folder on the "cd" line.
rem -k none switches off checksum checking. On Windows your own outgoing packets often
rem have "wrong" checksums because the network card fills them in later, and Suricata
rem would ignore them.

if "%~1"=="" (
    echo Usage: run_suricata.bat YOUR_IPV4_ADDRESS
    exit /b 1
)

cd /d "C:\Program Files\Suricata"
suricata.exe -c suricata.yaml -S "%~dp0local.rules" -i %1 -k none
