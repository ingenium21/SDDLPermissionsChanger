# SDDLPermissionsChanger
 
This all began because a client received the following High priority alert from the pen tester.


# AlertName: SMB Insecurely Configured Service

# AlertDescription:
"At least one insecurely configured Windows service was detected on the remote host. Unprivileged users can modify the properties of these affected services, allowing an unprivileged, local attacker to execute arbitrary code or commands as SYSTEM.

Nessus checked if any of the following groups have permissions to modify executable files that are started by Windows services :

- Everyone
- Users
- Domain Users
- Authenticated Users"

# AlertSolution:
"Ensure the groups listed above do not have ChangeConf, WDac, or WOwn
permissions. Refer to the Microsoft documentation for more
information."

So I did a lot of digging into sc.exe, combined that with some sleepless nights trying to figure out the regest and I wrote this script down.  You can run it, and give it a parameter of each of the four groups above.  It then loops through every service and uses `sc.exe sdshow {service}` to find the SDDL string.

Then it will parse according to the user you gave it, remove the two letters corresponding to the permissions.  The letter pairs are as follows:
- ChangeConf (DC)
- WDac (WD)
- WOwn (WO)

