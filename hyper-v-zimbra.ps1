$workdir = "$HOME\Documents"
# $guestuser = $env:USERNAME.ToLower()
$guestuser = 'administrator'
$sshpath = "$HOME\Documents\ssh-keys.pub"
if (!(Test-Path $sshpath)) {
  Write-Host "`n please configure `$sshpath or place a pubkey at $sshpath `n"
  exit
}
$sshpub = $(Get-Content $sshpath -raw).trim()

$config = $(Get-Content -path .\.distro -ea silentlycontinue | Out-String).trim()
if (!$config) {
  $config = 'bionic'
}

switch ($config) {
  'bionic' {
    $distro = 'ubuntu'
    $generation = 2
    $imgvers = "18.04"
    $imagebase = "https://cloud-images.ubuntu.com/releases/server/$imgvers/release"
    $sha256file = 'SHA256SUMS'
    $image = "ubuntu-$imgvers-server-cloudimg-amd64.img"
    $archive = ""
  }
  'focal' {
    $distro = 'ubuntu'
    $generation = 2
    $imgvers = "20.04"
    $imagebase = "https://cloud-images.ubuntu.com/releases/server/$imgvers/release"
    $sha256file = 'SHA256SUMS'
    $image = "ubuntu-$imgvers-server-cloudimg-amd64.img"
    $archive = ""
  }
}

$nettype = 'private' # private/public
$zwitch = 'Zimbra' # private or public switch name
$natnet = 'ZimbraNatNet' # private net nat net name (privnet only)
$adapter = 'Wi-Fi' # public net adapter name (pubnet only)

$cpus = 2
$ram = '4GB'
$hdd = '40GB'

$cidr = switch ($nettype) {
  'private' { '10.10.10' }
  'public' { $null }
}

$macs = @(
  '0247F6C235D0', # mail1
  '02E1136852D1', # mail2
  '0223FF85A7D2', # mail3
  '0223FF85A7D3'  # mail4
)

$fqdns = @(
  'mail.domain1.com', # mail1
  'mail.domain2.com', # mail2
  'mail.domain3.com', # mail3
  'mail.domain4.com'  # mail4
)

$sshopts = @('-o LogLevel=ERROR', '-o StrictHostKeyChecking=no', '-o UserKnownHostsFile=/dev/null')

# ----------------------------------------------------------------------

$imageurl = "$imagebase/$image$archive"
$srcimg = "$workdir\$image"
$vhdxtmpl = "$workdir\$($image -replace '^(.+)\.[^.]+$', '$1').vhdx"


# switch to the script directory
Set-Location $PSScriptRoot | Out-Null

# stop on any error
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$etchosts = "$env:windir\System32\drivers\etc\hosts"

# note: network configs version 1 an 2 didn't work
function Get-Metadata($vmname, $cblock, $ip) {
  if (!$cblock) {
    return @"
instance-id: id-$($vmname)
local-hostname: mail
"@
  }
  else {
    return @"
instance-id: id-$vmname
network-interfaces: |
  auto eth0
  iface eth0 inet static
  address $($cblock).$($ip)
  network $($cblock).0
  netmask 255.255.255.0
  broadcast $($cblock).255
  gateway $($cblock).1
local-hostname: mail
"@
  }
}

function Get-UserdataShared($cblock, $ip, $fqdn) {
  return @"
#cloud-config

mounts:
  - [ swap ]

users:
  - name: root
    ssh_authorized_keys:
$($sshpub.Replace("ssh-rsa","      - ssh-rsa"))
    sudo: [ 'ALL=(ALL) NOPASSWD:ALL' ]
    groups: [ sudo ]
    shell: /bin/bash
    # lock_passwd: false # passwd won't work without this
    # passwd: '`$6`$rounds=4096`$byY3nxArmvpvOrpV`$2M4C8fh3ZXx10v91yzipFRng1EFXTRNDE3q9PvxiPc3kC7N/NHG8HiwAvhd7QjMgZAXOsuBD5nOs0AJkByYmf/' # 'test'

write_files:
  # resolv.conf hard-set is a workaround for intial setup
  - path: /etc/resolv.conf
    content: |
      nameserver 8.8.4.4
      nameserver 8.8.8.8
  - path: /etc/systemd/resolved.conf
    content: |
      [Resolve]
      DNS=8.8.4.4
      FallbackDNS=8.8.8.8
  - path: /tmp/append-etc-hosts
    content: |
      $(Set-HostsFile -cblock $cblock -ip $ip -fqdn $fqdn -prefix '      ')
  - path: /etc/modules-load.d/zimbra.conf
    content: |
      br_netfilter
  - path: /etc/sysctl.d/zimbra.conf
    content: |
      net.bridge.bridge-nf-call-ip6tables = 1
      net.bridge.bridge-nf-call-iptables = 1
      net.bridge.bridge-nf-call-arptables = 1
      net.ipv4.ip_forward = 1
"@
}

function Get-UserdataUbuntu($cblock, $ip, $fqdn) {
return @"
$(Get-UserdataShared -cblock $cblock -ip $ip -fqdn $fqdn)
  - path: /etc/systemd/network/99-default.link
    content: |
      [Match]
      Path=/devices/virtual/net/*
      [Link]
      NamePolicy=kernel database onboard slot path
      MACAddressPolicy=none
  # https://github.com/clearlinux/distribution/issues/39
  - path: /etc/chrony/chrony.conf
    content: |
      refclock PHC /dev/ptp0 trust poll 2
      makestep 1 -1
      maxdistance 16.0
      #pool pool.ntp.org iburst
      driftfile /var/lib/chrony/chrony.drift
      logdir /var/log/chrony
package_upgrade: true
packages:
  - linux-tools-virtual
  - linux-cloud-tools-virtual
  - chrony
  - wget
runcmd:
  - mkdir -p /home/$guestuser
  - echo "sudo tail -f /var/log/syslog" > /home/$guestuser/log
  - systemctl mask --now systemd-timesyncd
  - systemctl enable --now chrony
  - cat /tmp/append-etc-hosts >> /etc/hosts
  - wget https://raw.githubusercontent.com/nvtienanh/zimbra-automated-installation/master/ZimbraEasyInstall.sh -O /root/ZimbraEasyInstall.sh
  - chmod +x /root/ZimbraEasyInstall.sh
  - touch /home/$guestuser/.init-completed
power_state:
  timeout: 300
  mode: reboot
"@
}

function New-PublicNet($zwitch, $adapter) {
  New-VMSwitch -name $zwitch -allowmanagementos $true -netadaptername $adapter | Format-List
}

function New-PrivateNet($natnet, $zwitch, $cblock) {
  New-VMSwitch -name $zwitch -switchtype internal | Format-List
  New-NetIPAddress -ipaddress "$($cblock).1" -prefixlength 24 -interfacealias "vEthernet ($zwitch)" | Format-List
  New-NetNat -name $natnet -internalipinterfaceaddressprefix "$($cblock).0/24" | Format-List
}

function Write-YamlContents($path, $cblock, $ip, $fqdn) {
  Set-Content $path ([byte[]][char[]] `
      "$(&"Get-Userdata$distro" -cblock $cblock -ip $ip -fqdn $fqdn)`n") -encoding byte
}

function Write-ISOContents($vmname, $cblock, $ip, $fqdn) {
  mkdir $workdir\$vmname\cidata -ea 0 | Out-Null
  Set-Content $workdir\$vmname\cidata\meta-data ([byte[]][char[]] `
      "$(Get-Metadata -vmname $vmname -cblock $cblock -ip $ip)") -encoding byte
  Write-YamlContents -path $workdir\$vmname\cidata\user-data -cblock $cblock -ip $ip -fqdn $fqdn
}

function New-ISO($vmname) {
  $fsi = new-object -ComObject IMAPI2FS.MsftFileSystemImage
  $fsi.FileSystemsToCreate = 3
  $fsi.VolumeName = 'cidata'
  $vmdir = (resolve-path -path "$workdir\$vmname").path
  $path = "$vmdir\cidata"
  $fsi.Root.AddTreeWithNamedStreams($path, $false)
  $isopath = "$vmdir\$vmname.iso"
  $res = $fsi.CreateResultImage()
  $cp = New-Object CodeDom.Compiler.CompilerParameters
  $cp.CompilerOptions = "/unsafe"
  if (!('ISOFile' -as [type])) {
    Add-Type -CompilerParameters $cp -TypeDefinition @"
      public class ISOFile {
        public unsafe static void Create(string iso, object stream, int blkSz, int blkCnt) {
          int bytes = 0; byte[] buf = new byte[blkSz];
          var ptr = (System.IntPtr)(&bytes); var o = System.IO.File.OpenWrite(iso);
          var i = stream as System.Runtime.InteropServices.ComTypes.IStream;
          if (o != null) { while (blkCnt-- > 0) { i.Read(buf, blkSz, ptr); o.Write(buf, 0, bytes); }
            o.Flush(); o.Close(); }}}
"@ 
  }
  [ISOFile]::Create($isopath, $res.ImageStream, $res.BlockSize, $res.TotalBlocks)
}

function New-Machine($zwitch, $vmname, $cpus, $mem, $hdd, $vhdxtmpl, $cblock, $ip, $mac, $fqdn) {
  $vmdir = "$workdir\$vmname"
  $vhdx = "$workdir\$vmname\$vmname.vhdx"

  New-Item -itemtype directory -force -path $vmdir | Out-Null

  if (!(Test-Path $vhdx)) {
    Copy-Item -path $vhdxtmpl -destination $vhdx -force
    Resize-VHD -path $vhdx -sizebytes $hdd

    Write-ISOContents -vmname $vmname -cblock $cblock -ip $ip -fqdn $fqdn
    # New-ISO -vmname $vmname
    Copy-Item "$workdir\isos\$vmname.iso" -Destination "$workdir\$vmname"

    $vm = New-VM -name $vmname -memorystartupbytes $mem -generation $generation `
      -switchname $zwitch -vhdpath $vhdx -path $workdir

    if ($generation -eq 2) {
      Set-VMFirmware -vm $vm -enablesecureboot off
    }

    Set-VMProcessor -vm $vm -count $cpus
    Add-VMDvdDrive -vmname $vmname -path $workdir\$vmname\$vmname.iso

    if (!$mac) { $mac = New-MacAddress }

    Get-VMNetworkAdapter -vm $vm | Set-VMNetworkAdapter -staticmacaddress $mac
    Set-VMComPort -vmname $vmname -number 2 -path \\.\pipe\$vmname
  }
  Start-VM -name $vmname
}

# Write ISO file to local machine
function Write-ISO($zwitch, $vmname, $cpus, $mem, $hdd, $vhdxtmpl, $cblock, $ip, $mac, $fqdn) {
  $vmdir = "$workdir\$vmname"
  $vhdx = "$workdir\$vmname\$vmname.vhdx"
  New-Item -itemtype directory -force -path $vmdir | Out-Null
  if (!(Test-Path $vhdx)) {
    Copy-Item -path $vhdxtmpl -destination $vhdx -force
    Resize-VHD -path $vhdx -sizebytes $hdd

    Write-ISOContents -vmname $vmname -cblock $cblock -ip $ip -fqdn $fqdn
    New-ISO -vmname $vmname
  }
}

function Remove-Machine($name) {
  Stop-VM $name -turnoff -confirm:$false -ea silentlycontinue
  Remove-VM $name -force -ea silentlycontinue
  Remove-Item -recurse -force $workdir\$name
}

function Remove-PublicNet($zwitch) {
  Remove-VMswitch -name $zwitch -force -confirm:$false
}

function Remove-PrivateNet($zwitch, $natnet) {
  Remove-VMswitch -name $zwitch -force -confirm:$false
  Remove-NetNat -name $natnet -confirm:$false
}

function New-MacAddress() {
  return "02$((1..5 | ForEach-Object { '{0:X2}' -f (get-random -max 256) }) -join '')"
}

function basename($path) {
  return $path.substring(0, $path.lastindexof('.'))
}

function New-VHDXTmpl($imageurl, $srcimg, $vhdxtmpl) {
  if (!(Test-Path $workdir)) {
    mkdir $workdir | Out-Null
  }
  if (!(Test-Path $srcimg$archive)) {
    Get-File -url $imageurl -saveto $srcimg$archive
  }

  Get-Item -path $srcimg$archive | ForEach-Object { Write-Host 'srcimg:', $_.name, ([math]::round($_.length / 1MB, 2)), 'MB' }

  if ($sha256file) {
    $hash = shasum256 -shaurl "$imagebase/$sha256file" -diskitem $srcimg$archive -item $image$archive
    Write-Output "checksum: $hash"
  }
  else {
    Write-Output "no sha256file specified, skipping integrity ckeck"
  }

  if (($archive -eq '.tar.gz') -and (!(Test-Path $srcimg))) {
    tar xzf $srcimg$archive -C $workdir
  }
  elseif (($archive -eq '.xz') -and (!(Test-Path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }
  elseif (($archive -eq '.bz2') -and (!(Test-Path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }

  if (!(Test-Path $vhdxtmpl)) {
    qemu-img.exe convert $srcimg -O vhdx -o subformat=dynamic $vhdxtmpl
  }

  Write-Output ''
  Get-Item -path $vhdxtmpl | ForEach-Object { Write-Host 'vhxdtmpl:', $_.name, ([math]::round($_.length / 1MB, 2)), 'MB' }
  return
}

function Get-File($url, $saveto) {
  Write-Output "downloading $url to $saveto"
  $progresspreference = 'silentlycontinue'
  Invoke-Webrequest $url -usebasicparsing -outfile $saveto # too slow w/ indicator
  $progresspreference = 'continue'
}

function Set-HostsFile($cblock, $ip, $fqdn, $prefix) {
  $ret = switch ($nettype) {
    'private' {
      @"
#
$prefix#
$prefix$($cblock).$ip $fqdn mail
$prefix#
$prefix#
"@
    }
    'public' {
      ''
    }
  }
  return $ret
}

function Set-HyperVHostsFile($cblock, $ip, $fqdn, $prefix) {
  $ret = switch ($nettype) {
    'private' {
      @"
#
$prefix#
$prefix$($cblock).$ip $fqdn
$prefix#
$prefix#
"@
    }
    'public' {
      ''
    }
  }
  return $ret
}

function Update-HostsFile($cblock, $ip, $fqdn) {
  Set-HyperVHostsFile -cblock $cblock -ip $ip -fqdn $fqdn -prefix '' | Out-File -encoding utf8 -append $etchosts
  Get-Content $etchosts
}


function Get-ZimbraVM() {
  return get-vm | Where-Object { ($_.name -match 'mail.*') }
}

function get-our-running-vms() {
  return get-vm | Where-Object { ($_.state -eq 'running') -and ($_.name -match 'mail.*') }
}

function shasum256($shaurl, $diskitem, $item) {
  $pat = "^(\S+)\s+\*?$([regex]::escape($item))$"

  $hash = Get-Filehash -algo sha256 -path $diskitem | ForEach-Object { $_.hash }

  $webhash = ( Invoke-Webrequest $shaurl -usebasicparsing ).tostring().split("`n") | `
    Select-String $pat | ForEach-Object { $_.matches.groups[1].value }

  if (!($hash -ieq $webhash)) {
    throw @"
    SHA256 MISMATCH:
       shaurl: $shaurl
         item: $item
     diskitem: $diskitem
     diskhash: $hash
      webhash: $webhash
"@
  }
  return $hash
}

function Get-Ctrlc() {
  if ([console]::KeyAvailable) {
    $key = [system.console]::readkey($true)
    if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
      return $true
    }
  }
  return $false;
}

function Wait-NodeInit($opts, $name) {
  while ( ! $(ssh $opts $guestuser@master 'ls ~/.init-completed 2> /dev/null') ) {
    Write-Output "waiting for $name to init..."
    Start-Sleep -seconds 5
    if ( Get-Ctrlc ) { exit 1 }
  }
}

function Convert-UNCPath($path) {
  $item = Get-Item $path
  return $path.replace($item.root, '/').replace('\', '/')
}

function Convert-UNCPath2($path) {
  return ($path -replace '^[^:]*:?(.+)$', "`$1").replace('\', '/')
}

Write-Output ''

if ($args.count -eq 0) {
  $args = @( 'help' )
}

switch -regex ($args) {
  ^help$ {
    Write-Output @"
  Practice real Kubernetes configurations on a local multi-node cluster.
  Inspect and optionally customize this script before use.

  Usage: .\hyper-v-zimbra.ps1 command+

  Commands:

         Deploy-Network - Install private or public host network
       Add-HostsFileVM1 - Append private network node names to etc/hosts
              Get-Image - Download the VM image
          New-ZimbraVMN - Create and launch Zimbra Mail VM (Mail1, Mail2, ...)
        Start-ZimbraVMN - Install Zimbra Mail VM (Mail1, Mail2, ...)
      Save-ISOZimbraVMN - Save Zimbra Mail iso (Mail1, Mail2, ...)
               Get-Info - Display info about nodes
       Restart-ZimbraVM - Soft-reboot the nodes
        Invoke-Shutdown - Soft-shutdown the nodes
          Save-ZimbraVM - Snapshot the VMs
       Restore-ZimbraVM - Restore VMs from latest snapshots
          Stop-ZimbraVM - Stop the VMs
         Start-ZimbraVM - Start the VMs
        Remove-ZimbraVM - Stop VMs and delete the VM files
         Remove-Network - Delete the network
"@
  }
  ^Deploy-Network$ {
    switch ($nettype) {
      'private' { New-PrivateNet -natnet $natnet -zwitch $zwitch -cblock $cidr }
      'public' { New-PublicNet -zwitch $zwitch -adapter $adapter }
    }
  }
  ^Show-Macs$ {
    $cnt = 10
    0..$cnt | ForEach-Object {
      $comment = switch ($_) { 0 { 'master' } default { "mail$_" } }
      $comma = if ($_ -eq $cnt) { '' } else { ',' }
      Write-Output "  '$(New-MacAddress)'$comma # $comment"
    }
  }
  ^Get-Image$ {
    New-VHDXTmpl -imageurl $imageurl -srcimg $srcimg -vhdxtmpl $vhdxtmpl
  }
  '(^Add-HostsFileVM(?<number>\d+)$)' {
    $num = [int]$matches.number
    $fqdn = $fqdns[$num-1]  
    switch ($nettype) {
      'private' { Update-HostsFile -cblock $cidr -ip $($num + 10) -fqdn $fqdn}
      'public' { Write-Output "not supported for public net - use dhcp" }
    }
  }
  '(^New-ZimbraVM(?<number>\d+)$)' {
    $num = [int]$matches.number
    $name = "mail$($num)"
    $fqdn = $fqdns[$num-1]    
    New-Machine -zwitch $zwitch -vmname $name -cpus $cpus `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip $($num + 10) -mac $macs[$num-1] -fqdn $fqdn
  }
  '(^Start-ZimbraVM(?<number>\d+)$)' {
    $num = [int]$matches.number
    $fqdn = $fqdns[$num-1]
    $domain = $fqdn.split(".",2)[1]
    $command = "./ZimbraEasyInstall.sh $domain --ip $cidr.$($num + 10) --password Zimbra2017 --keystrokes /root/installZimbra-keystrokes --zimbrascript /root/installZimbraScript"
    cmd.exe /c "ssh $sshopts root@$fqdn $command 2>&1"
    if (!$?) {
      Write-Output "master init has failed, aborting"
      exit 1
    }
  }
  '(^Save-ISOZimbraVM(?<number>\d+)$)' {
    $num = [int]$matches.number
    $name = "mail$($num)"
    Write-ISO -zwitch $zwitch -vmname $name -cpus $cpus `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip $($num + 10) -mac $macs[$num-1] -fqdn $fqdns[$num-1]
  }
  ^Get-Info$ {
    Get-ZimbraVM
  }  
  ^Restart-ZimbraVM$ {
    Get-ZimbraVM | ForEach-Object { $node = $_.name; $(ssh $sshopts $guestuser@$node 'sudo reboot') }
  }
  ^Invoke-Shutdown$ {
    Get-ZimbraVM | ForEach-Object { $node = $_.name; $(ssh $sshopts $guestuser@$node 'sudo shutdown -h now') }
  }
  ^Save-ZimbraVM$ {
    Get-ZimbraVM | Checkpoint-VM
  }
  ^Restore-ZimbraVM$ {
    Get-ZimbraVM | Foreach-Object { $_ | Get-VMSnapshot | Sort-Object creationtime | `
        Select-Object -last 1 | Restore-VMSnapshot -confirm:$false }
  }
  ^Stop-ZimbraVM$ {
    Get-ZimbraVM | Stop-VM
  }
  ^Start-ZimbraVM$ {
    Get-ZimbraVM | Start-VM
  }
  ^Remove-ZimbraVM$ {
    Get-ZimbraVM | ForEach-Object { Remove-Machine -name $_.name }
  }
  ^Remove-Network$ {
    switch ($nettype) {
      'private' { Remove-PrivateNet -zwitch $zwitch -natnet $natnet }
      'public' { Remove-PublicNet -zwitch $zwitch }
    }
  }
  ^Get-Time$ {
    Write-Output "local: $(Get-date)"
    Get-ZimbraVM | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      # ssh $sshopts $guestuser@$node "date ; if which chronyc > /dev/null; then sudo chronyc makestep ; date; fi"
      ssh $sshopts $guestuser@$node "date"
    }
  }
  ^Start-Track$ {
    Get-ZimbraVM | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      ssh $sshopts $guestuser@$node "date ; sudo chronyc tracking"
    }
  }
  default {
    Write-Output 'invalid command; try: .\hyper-v-zimbra.ps1 help'
  }
}

Write-Output ''
