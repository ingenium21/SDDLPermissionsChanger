# SDDLPermissionsChanger
This script will check all of your services, see if Everyone, Users, Domain Users, or Authenticated users has Change Config, Change Permissions, and Change Ownership rights for the service.
This can be a security concern because your service would be vulnerable to an elevation-of-privilege attack.
These permissions enable a designee to change the configuration of the service to include the binary file that is run when the service is started. 



This all began because a client received the following High priority alert from the pen tester.
# AlertName: 
SMB Insecurely Configured Service

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

So I did a lot of digging into sc.exe, combined that with some sleepless nights trying to figure out how to create a security descriptor object and figure out how to removeAcess in the SD object and what that looks like. \

Then it will parse according to the user you gave it, remove the two letters corresponding to the permissions.  The letter pairs are as follows:
- ChangeConf (DC)
- WDac (WD)
- WOwn (WO)

