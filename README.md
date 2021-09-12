# Hyper-V Zimbra 
Script to create Zimbra mail server on Microsoft Hyper-V Server

- Create `ssh-keys.pub` contains ssh public key of clients that you want access to mail server. The ssh key of Hyper-V server is required. For example:

```txt
ssh-rsa AAAAB3NzaC1yc2EAA.............. administrator@hyper-v
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ............. user@Windown10
```

## On windows 10

Copy `ssh-keys.pub` to `C:\Users\youraccount\Documents`

```powershell
.\hyper-v-zimbra.ps1 Get-Image
.\hyper-v-zimbra.ps1 Save-ISOZimbraVM1
```

A new folder `mail1` will be create on `C:\Users\youraccount\Documents`

## Hyper-V Server

- Open Windows Admin Center then upload `ssh-keys.pub` to `C:\Users\Admininstrator\Documents` and `C:\Users\youraccount\Documents\mail1\mail1.iso` to `C:\Users\Admininstrator\Documents\isos`

```powershell
.\hyper-v-zimbra.ps1 Get-Image
.\hyper-v-zimbra.ps1 Deploy-Network
.\hyper-v-zimbra.ps1 New-ZimbraVM1
.\hyper-v-zimbra.ps1 Add-HostsFileVM1
.\hyper-v-zimbra.ps1 Start-ZimbraVM1
```

## Add static mapping

```Powershell
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 2223 -Protocol TCP -InternalIPAddress "10.10.10.11" -InternalPort 22 -NatName ZimbraNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 80 -Protocol TCP -InternalIPAddress "10.10.10.11" -InternalPort 80 -NatName ZimbraNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 443 -Protocol TCP -InternalIPAddress "10.10.10.11" -InternalPort 443 -NatName ZimbraNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 7071 -Protocol TCP -InternalIPAddress "10.10.10.11" -InternalPort 7071 -NatName ZimbraNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 25 -Protocol TCP -InternalIPAddress "10.10.10.11" -InternalPort 25 -NatName ZimbraNatNet
```

## Demo

- [Microsoft Hyper-V Server: Create a Zimbra mail server](https://youtu.be/VgifWoXsaQg)

