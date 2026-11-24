#Requires -RunAsAdministrator
# Fix-2-Service : 서비스에 영향을 줄 수 있는 항목 조치 (W-01 16 17 21 22 24 44 64 + 잔여 작업 W-37)
# 실행: powershell -ExecutionPolicy Bypass -File .\Fix-2-Service.ps1        ( ? = Where-Object , % = ForEach-Object )
if ('가'.Length -ne 1) { 'Save this file as UTF-8 with BOM'; return }      # 한글 인코딩 확인
$ErrorActionPreference = 'Stop'; $bak = 'C:\check\backup2'; $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
$site = 'Webhard'; $subnet = '172.2.3.0'; $mask = '255.255.255.0'          # FTP 사이트 이름, 접속을 허용할 랜 대역
$au = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-11').Translate([Security.Principal.NTAccount]).Value   # Authenticated Users
$loc = @{ PSPath = 'MACHINE/WEBROOT/APPHOST'; Location = $site }           # IIS FTP 사이트 설정 위치
Write-Host "■ Fix-2 조치 (영향 확인 항목)   $env:COMPUTERNAME   $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Cyan

# Fix   : 조치 1건을 y/n 으로 확인한 뒤 실행하고 [완료] / [실패] / [건너뜀] 으로 한 줄 출력
# SetAcl: 폴더 권한에서 Users 의 수정 권한을 제거하고, 필요하면 다른 계정에 권한을 추가
function Fix($code, $name, $desc, [scriptblock]$do) {
    if ((Read-Host "  $code $name - $desc  실행할까요? (y/n)") -ne 'y') { Write-Host "  [건너뜀] $code $name" -ForegroundColor Yellow; return }
    try { $global:LASTEXITCODE = 0; & $do | Out-Null; if ($LASTEXITCODE) { throw "종료 코드 $LASTEXITCODE" }
          Write-Host "  [완료] $code $name" -ForegroundColor Green }
    catch { Write-Host "  [실패] $code $name  ($($_.Exception.Message))" -ForegroundColor Red }
}
function SetAcl($path, $add = $null, $right = 'Modify') {
    $acl = Get-Acl $path
    $acl.Access | ? { $_.IdentityReference -match 'BUILTIN\\Users' -and -not $_.IsInherited -and $_.FileSystemRights -match 'Modify' } | % { [void]$acl.RemoveAccessRule($_) }
    if ($add) { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($add, $right, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
    Set-Acl $path $acl
}

# --- 0. 백업: 조치 전 설정을 저장 ---
New-Item $bak -ItemType Directory -Force | Out-Null
Copy-Item "$env:windir\system32\inetsrv\config\applicationHost.config" "$bak\applicationHost_before.config"      # IIS/FTP 설정
Get-SmbShareAccess Share | Export-Csv "$bak\share_access_before.csv" -NoTypeInformation -Encoding UTF8
icacls C:\Share /save "$bak\acl_share.txt" | Out-Null; icacls C:\webhard /save "$bak\acl_webhard.txt" | Out-Null
netsh advfirewall export "$bak\firewall_before.wfw" | Out-Null
Write-Host "  백업 완료: $bak`n" -ForegroundColor DarkGray

# --- 1. 계정·공유·서비스 ---
Fix W-37 'SyncToSlave작업비활성화' '삭제된 슬레이브로 동기화하던 잔여 작업' { Disable-ScheduledTask -TaskName SyncToSlave }
Fix W-01 'Administrator계정명변경' 'Administrator -> svradmin (이후 로그인 이름이 바뀝니다)' { Rename-LocalUser -Name Administrator -NewName svradmin }
Fix W-16 '공유권한설정' 'Share: Everyone 제거 -> 인증된 사용자 읽기, NTFS Users 수정 권한 제거' {
    Revoke-SmbShareAccess -Name Share -AccountName Everyone -Force
    Grant-SmbShareAccess -Name Share -AccountName $au -AccessRight Read -Force
    SetAcl C:\Share
}
Fix W-17 '기본공유제거' 'AutoShareServer=0, C$ 공유 삭제' {
    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoShareServer -Value 0 -PropertyType DWord -Force
    net share 'C$' /delete /y
}
Fix W-44 '원격레지스트리' '서비스 중지 + 사용 안 함' { Stop-Service RemoteRegistry -Force -EA SilentlyContinue; Set-Service RemoteRegistry -StartupType Disabled }

# --- 2. FTP (IIS) ---
Import-Module WebAdministration
Fix W-21 'FTP암호화' '자체 서명 인증서를 만들고 SSL 필수로 설정' {
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)
    $ssl = "/[name='$site'].ftpServer.security.ssl"
    & $appcmd set config -section:system.applicationHost/sites "$ssl.serverCertHash:$($cert.Thumbprint)" "$ssl.controlChannelPolicy:SslRequire" "$ssl.dataChannelPolicy:SslRequire" /commit:apphost
}
Fix W-22 'FTP디렉터리권한' 'FTPUsers 그룹(user1)만 읽기·쓰기 허용, Users 수정 권한 제거' {
    if (-not (Get-LocalGroup FTPUsers -EA 0)) { New-LocalGroup FTPUsers -Description 'FTP 접속 허용 계정' }
    Add-LocalGroupMember FTPUsers user1 -EA SilentlyContinue
    SetAcl C:\webhard FTPUsers Modify
    $f = '/system.ftpServer/security/authorization'              # FTP 권한 부여 규칙: users=* 규칙을 지우고 FTPUsers 그룹만 허용
    Clear-WebConfiguration -Filter $f @loc
    Add-WebConfiguration -Filter $f -Value @{ accessType = 'Allow'; roles = 'FTPUsers'; permissions = 'Read,Write' } @loc
}
Fix W-24 'FTP접근제어' "접속 허용 IP를 $subnet/24 와 로컬로 제한" {
    $f = '/system.ftpServer/security/ipSecurity'
    Set-WebConfigurationProperty -Filter $f -Name allowUnlisted -Value $false @loc
    Add-WebConfiguration -Filter $f -Value @{ ipAddress = $subnet; subnetMask = $mask; allowed = $true } @loc
    Add-WebConfiguration -Filter $f -Value @{ ipAddress = '127.0.0.1'; allowed = $true } @loc
}
Restart-Service ftpsvc -Force; Write-Host '  FTP 서비스를 다시 시작했습니다' -ForegroundColor DarkGray

# --- 3. 방화벽: 원격 주소가 Any 인 위험 포트(135, 137~139, 445, 3389, 5985, 포트 범위) 규칙을 같은 대역으로 제한 ---
Fix W-64 '방화벽설정' '위험 포트 규칙의 원격 주소를 LocalSubnet(같은 대역)으로 제한' {
    $n = 0
    Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | % {
        $p = ($_ | Get-NetFirewallPortFilter).LocalPort -join ','
        $any = ($_ | Get-NetFirewallAddressFilter).RemoteAddress -eq 'Any'
        if ($any -and $p -match '(^|,)(135|137|138|139|445|3389|5985)(,|$)|\d+-\d+') { $_ | Set-NetFirewallRule -RemoteAddress LocalSubnet; $n++ }
    }
    Write-Host "    변경된 규칙 ${n}개" -ForegroundColor DarkGray
}

Write-Host "`n▶ 백업 위치 : $bak" -ForegroundColor Cyan
Write-Host '※ Administrator 계정 이름이 svradmin 으로 바뀌었습니다. 점검 스크립트(A~D)로 결과를 확인하세요.' -ForegroundColor Yellow
