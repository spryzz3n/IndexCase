# Lab setup

An isolated Active Directory lab on Proxmox, used to generate real Windows
event logs for IndexCase. This file records what has been built, in order, and
what is still to do.

Credentials and host details are kept out of the repository in
`lab/credentials.local.md` (ignored by git).

## Design

| Decision | Choice | Why |
|---|---|---|
| Hypervisor | Proxmox VE 9 | Existing host with spare memory |
| Network | New bridge `vmbr1`, no uplink, no host address | Lab traffic never reaches the LAN or the internet |
| Addressing | Static, `10.10.10.0/24`, no gateway | The LAN has no DHCP, and the lab needs none |
| OS | Windows Server 2022 evaluation for every Windows VM | One ISO; runs in 2 GB; same Security and Sysmon events as a desktop OS |
| VM hardware | SATA disk, Intel e1000 NIC, SeaBIOS | Drivers built into Windows, so no virtio driver ISO is needed |
| VM IDs | 900–909 | Clear of the host's other VMs |
| Memory budget | 16.5 GB total | Leaves headroom for the host's other VMs |

### Addresses

| Host | Role | IP | DNS server |
|---|---|---|---|
| dc01 | Domain controller, DNS | 10.10.10.10 | 127.0.0.1 |
| ws01–ws06 | Domain members (workstations) | 10.10.10.21–26 | 10.10.10.10 |
| attacker | Source of the remote-execution tests | 10.10.10.100 | 10.10.10.10 |

### VMs

| ID | Name | RAM | Disk | Status |
|---|---|---|---|---|
| 900 | dc01 | 3 GB | 60 GB | Built, domain controller for `lab.local` |
| 901–906 | ws01–ws06 | 2 GB each | linked to template | To do |
| 907 | attacker | 1.5 GB | | To do |
| 909 | ws-template | 2 GB | 40 GB | To do |

### Domain

- Domain `lab.local`, NetBIOS name `LAB`.
- OUs under `OU=Lab,DC=lab,DC=local`:

| OU | Contents |
|---|---|
| Workstations | ws01–ws06; the audit and Sysmon policy targets this OU |
| Staff | alice, bob, carol, dave (normal users) |
| Admins | helpdesk1, helpdesk2 (local admin on every workstation) |
| Service | svc_sccm (background service account, source of routine logons) |

- Group `Workstations Admins` (in the Admins OU): helpdesk1, helpdesk2,
  svc_sccm. It is made local administrator on every workstation.
- New computer accounts are created in the Workstations OU.

## Done

### 1. Host: isolated bridge

Added to `/etc/network/interfaces` (a backup of the original was taken first)
and brought up with `ip link`, without reloading any existing interface:

```
auto vmbr1
iface vmbr1 inet manual
	bridge-ports none
	bridge-stp off
	bridge-fd 0
```

```
ip link add name vmbr1 type bridge stp_state 0 forward_delay 0
ip link set vmbr1 up
```

### 2. Host: installation media

- Windows Server 2022 evaluation ISO in `local:iso/SERVER_EVAL_2022_x64FRE_en-us.iso`.
- QEMU guest agent installer (`qemu-ga-x86_64.msi`) on the host, for later.
- The full virtio driver ISO was skipped: the mirror was very slow, and SATA
  plus e1000 need no extra drivers.

### 3. dc01: VM

```
qm create 900 --name dc01 --memory 3072 --cores 2 --ostype win11 \
  --net0 e1000,bridge=vmbr1 \
  --sata0 local-lvm:60 \
  --ide2 local:iso/SERVER_EVAL_2022_x64FRE_en-us.iso,media=cdrom \
  --boot order=ide2 --agent 1 --vga std
qm start 900
```

`--ostype win2022` is not accepted by this Proxmox version; `win11` is the
closest value and works with SeaBIOS.

### 4. dc01: Windows install

Windows Server 2022 Standard (Desktop Experience), custom install on the 60 GB
disk, Administrator password set.

### 5. dc01: static IP

```powershell
Get-NetAdapter                      # adapter name: Ethernet
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 127.0.0.1
ipconfig /all                       # check address and DNS server
```

### 6. dc01: rename

```powershell
Rename-Computer -NewName DC01 -Restart
```

### 7. dc01: Active Directory

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName lab.local -DomainNetbiosName LAB -InstallDns
Get-ADDomain | Select-Object DNSRoot, NetBIOSName    # lab.local, LAB
```

The forest install asks for the Directory Services Restore Mode password and
reboots on its own. The first login afterwards is slow.

### 8. dc01: OUs

```powershell
New-ADOrganizationalUnit -Name Lab
"Workstations","Staff","Admins","Service" | % {
    New-ADOrganizationalUnit -Name $_ -Path "OU=Lab,DC=lab,DC=local" }
Get-ADOrganizationalUnit -Filter * | Select-Object Name
```

### 9. dc01: user accounts

```powershell
$pw = Read-Host -AsSecureString "Password"
"alice","bob","carol","dave" | % { New-ADUser -Name $_ -SamAccountName $_ `
    -Path "OU=Staff,OU=Lab,DC=lab,DC=local" -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true }
"helpdesk1","helpdesk2" | % { New-ADUser -Name $_ -SamAccountName $_ `
    -Path "OU=Admins,OU=Lab,DC=lab,DC=local" -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true }
"svc_sccm" | % { New-ADUser -Name $_ -SamAccountName $_ `
    -Path "OU=Service,OU=Lab,DC=lab,DC=local" -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true }
Get-ADUser -Filter * -SearchBase "OU=Lab,DC=lab,DC=local" | Select-Object SamAccountName, Enabled
```

### 10. dc01: admin group and default computer OU

A group, rather than individual accounts, so one setting makes all three
local administrators on every workstation. `redircmp` sends newly joined
computers to the Workstations OU instead of the default Computers container,
so the audit policy linked to that OU reaches them.

```powershell
New-ADGroup -Name "Workstations Admins" -GroupScope Global -Path "OU=Admins,OU=Lab,DC=lab,DC=local"
Add-ADGroupMember "Workstations Admins" -Members helpdesk1,helpdesk2,svc_sccm
redircmp "OU=Workstations,OU=Lab,DC=lab,DC=local"     # Redirection was successful.
Get-ADGroupMember "Workstations Admins" | Select-Object Name
```

## To do

Each step will be filled in with the exact commands once it has been run.

11. **Workstation template (VM 909).** Install Windows Server 2022 once, add
    the QEMU guest agent, generalise it with Sysprep, and convert it to a
    Proxmox template.
12. **Clone ws01–ws06 (VMs 901–906)** from the template.
13. **Per-workstation setup.** Static IP, DNS pointing at dc01, rename, join
    `lab.local`, add `LAB\Workstations Admins` to the local Administrators group.
14. **Audit policy GPO** linked to the Workstations OU and the Domain
    Controllers OU, covering every event IndexCase reads:

    | Events | Setting |
    |---|---|
    | 4624, 4625, 4648, 4672 | Logon/Logoff: Audit Logon, Audit Special Logon |
    | 4688 with command line | Detailed Tracking: Process Creation, plus "Include command line in process creation events" |
    | 4697 | System: Security System Extension |
    | 4698, 4699 | Object Access: Other Object Access Events |
    | 5140, 5145 | Object Access: File Share, Detailed File Share |
    | 4768, 4769 (DC) | Account Logon: Kerberos Authentication Service, Kerberos Service Ticket Operations |
    | 4776 (DC) | Account Logon: Credential Validation |
    | TaskScheduler 106/200/201 | Enable the Microsoft-Windows-TaskScheduler/Operational log |

    Plus "Force audit policy subcategory settings to override audit policy
    category settings" enabled.
15. **Log sizes.** Security log at least 1 GB, Sysmon at least 512 MB, so a
    scenario never rolls over.
16. **Sysmon** with the sysmon-modular configuration, deployed to every
    workstation and the DC.
17. **Clean snapshots** of every lab VM before the first scenario, so each
    scenario starts from the same state.
18. **Log export script** running `wevtutil epl` for Security, System,
    Sysmon, TaskScheduler and WMI-Activity on each host, collecting into
    `eval/scenarios/<id>/evtx/`.
19. **Attacker VM (907).**
20. **Scenarios T1–T5** from the evaluation plan, each with its
    `ground_truth.json`, exported, then the lab reverted to the clean
    snapshots.

## Notes

- Copy and paste do not work in the Proxmox console for Windows guests, so
  commands are typed. Tab completion helps.
- Use the console toolbar's Ctrl-Alt-Del button to reach the login prompt.

## Removing the lab

1. Stop and destroy VMs 900–909.
2. Delete the `vmbr1` block from `/etc/network/interfaces` (or restore the
   backup), then `ip link delete vmbr1`. Neither step affects `vmbr0` or other
   VMs.
3. Delete the ISO and the guest agent installer if no longer needed.
