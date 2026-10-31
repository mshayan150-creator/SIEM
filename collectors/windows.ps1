#Requires -Version 5.1
<# Live local Windows Event Log shipper. Run from an elevated PowerShell.
   One durable pending batch is retried unchanged. No Python installation required. #>
param(
    [Parameter(Mandatory=$true)][string]$ConfigFile,
    [string]$StateDirectory = '',
    [switch]$Once
)
$ErrorActionPreference = 'Stop'
$config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
$ApiUrl = [string]$config.api_url
$uri = [Uri]$ApiUrl
if ($uri.Scheme -ne 'https' -and !($uri.Scheme -eq 'http' -and $uri.IsLoopback)) { throw 'Use HTTPS except on loopback.' }
if ($uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') { throw 'Use a server origin without a path, query, or credentials.' }
if ($config.host -ine $env:COMPUTERNAME) { throw 'This configuration is registered to a different computer hostname.' }
if ($config.collector_id -notmatch '^[a-f0-9]{32}$' -or $config.token -notmatch '^[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$') { throw 'Invalid collector configuration.' }
$ApiUrl = $ApiUrl.TrimEnd('/')
$apiKey = [string]$config.token
if (!$StateDirectory) { $StateDirectory = Join-Path $env:LOCALAPPDATA "SIEM-Collector\$($config.collector_id)" }
New-Item -ItemType Directory -Force -Path $StateDirectory | Out-Null
# Pending logs and state are readable only by this Windows user and SYSTEM.
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -Path $StateDirectory -AclObject $acl
$lock = [IO.File]::Open((Join-Path $StateDirectory 'collector.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
$statePath = Join-Path $StateDirectory 'state.json'
$pendingPath = Join-Path $StateDirectory 'pending.json'
$channels = @('Security','System','Application')
function Write-AtomicJson($Path, $Value) {
    $temp = "$Path.tmp"
    [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 15 -Compress), (New-Object Text.UTF8Encoding $false))
    if (Test-Path $Path) { [IO.File]::Replace($temp, $Path, $null) } else { [IO.File]::Move($temp, $Path) }
}
function Read-Events($Channel, $XPath, $Limit, [bool]$Oldest = $false) {
    try { return @(Get-WinEvent -LogName $Channel -FilterXPath $XPath -MaxEvents $Limit -Oldest:$Oldest -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }; throw }
}
function Normalize($Record) {
    [xml]$xml = $Record.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) { if ($item.Name) { $fields[[string]$item.Name] = [string]$item.'#text' } }
    $outcome = 'unknown'; $action = 'windows_event'; $ip = '127.0.0.1'; $user = 'SYSTEM'
    if ($Record.UserId) { $user = $Record.UserId.Value }
    if ($Record.LogName -eq 'Security' -and $Record.Id -in @(4624,4625)) {
        $outcome = if ($Record.Id -eq 4624) { 'success' } else { 'failure' }
        $user = [string]$fields.TargetUserName
        if ($fields.TargetDomainName -and $fields.TargetDomainName -ne '-') { $user = "$($fields.TargetDomainName)\$user" }
        if (!$user) { $user = 'unknown' }
        $parsed = $null
        $remote = [Net.IPAddress]::TryParse([string]$fields.IpAddress, [ref]$parsed)
        if ($remote -and $parsed.IsIPv4MappedToIPv6) { $parsed = $parsed.MapToIPv4() }
        $action = 'local_logon'
        if ($remote -and ![Net.IPAddress]::IsLoopback($parsed) -and $parsed.ToString() -notin @('0.0.0.0','::')) {
            $ip = $parsed.ToString().Split('%')[0]; $action = 'logon'
            # Recovered old events are indexed but must not create live arrival-time alerts.
            if (([DateTime]::UtcNow - $Record.TimeCreated.ToUniversalTime()).TotalSeconds -gt 60) { $action = 'historical_logon' }
        }
    }
    $message = [string]$Record.Message
    if (!$message) { $message = "Windows event $($Record.Id) from $($Record.ProviderName)" }
    if ($message.Length -gt 1500) { $message = $message.Substring(0,1500) }
    if ($user.Length -gt 256) { $user = $user.Substring(0,256) }
    return @{
        '@timestamp' = $Record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        event = @{ dataset = "windows.$($Record.LogName.ToLowerInvariant())"; outcome = $outcome; action = $action; code = [string]$Record.Id; id = "$env:COMPUTERNAME/$($Record.LogName)/$($Record.RecordId)" }
        host = @{ name = $env:COMPUTERNAME }; source = @{ ip = $ip }; user = @{ name = $user }; message = $message
    }
}
try {
    if (Test-Path $statePath) {
        $state = Get-Content $statePath -Raw | ConvertFrom-Json
        if ($state.id -ne $config.collector_id -or $state.api_url -ne $ApiUrl) { throw 'State belongs to a different server or collector. Use a different StateDirectory.' }
    }
    else {
        $cursors = @{}
        foreach ($channel in $channels) { $latest = @(Read-Events $channel '*' 1); $cursors[$channel] = if ($latest.Count) { [long]$latest[0].RecordId } else { 0 } }
        $state = [pscustomobject]@{ id = $config.collector_id; api_url = $ApiUrl; cursors = [pscustomobject]$cursors; sent = 0; local_auth = 0 }
        Write-AtomicJson $statePath $state
        Write-Host 'Live collection initialized. Existing history is skipped; new Windows events will be sent.'
    }
    do {
        $status = 'Watching Windows Event Logs'
        try {
            if (!(Test-Path $pendingPath)) {
                $events = @(); $next = @{}; $localCount = 0
                foreach ($channel in $channels) {
                    $cursor = [long]$state.cursors.$channel
                    $latest = @(Read-Events $channel '*' 1)
                    if ($latest.Count -and [long]$latest[0].RecordId -lt $cursor) { throw "Log reset detected for $channel. Stop and archive the state directory before restarting." }
                    $filter = "*[System[EventRecordID > $cursor]]"
                    if ($channel -eq 'Security') { $filter = "*[System[(EventID=4624 or EventID=4625) and EventRecordID > $cursor]]" }
                    $records = @(Read-Events $channel $filter 50 $true)
                    $next[$channel] = $cursor
                    foreach ($record in $records) {
                        $event = Normalize $record
                        if ($event.event.action -eq 'local_logon') { $localCount++ }
                        $events += $event; $next[$channel] = [long]$record.RecordId
                    }
                }
                if ($events.Count) {
                    $pending = @{ key = [Guid]::NewGuid().ToString(); created = [DateTime]::UtcNow.ToString('o'); body = (@{ events = @($events) } | ConvertTo-Json -Depth 12 -Compress); cursors = $next; sent = ([long]$state.sent + $events.Count); local_auth = ([long]$state.local_auth + $localCount) }
                    Write-AtomicJson $pendingPath $pending
                }
            }
            if (Test-Path $pendingPath) {
                $pending = Get-Content $pendingPath -Raw | ConvertFrom-Json
                if (([DateTime]::UtcNow - [DateTime]::Parse($pending.created).ToUniversalTime()).TotalHours -gt 23) { throw 'Pending batch exceeds safe retry age. Preserve pending.json and investigate before replaying.' }
                $headers = @{ Authorization = "Bearer $apiKey"; 'Idempotency-Key' = $pending.key }
                $result = Invoke-RestMethod -Uri "$ApiUrl/api/v1/telemetry" -Method Post -Headers $headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($pending.body)) -TimeoutSec 15
                $state.cursors = $pending.cursors; $state.sent = $pending.sent; $state.local_auth = $pending.local_auth
                Write-AtomicJson $statePath $state
                Remove-Item $pendingPath
                Write-Host "Accepted $($result.accepted) events; total $($state.sent)."
            }
        } catch { $status = 'Collection or delivery paused; inspect collector terminal'; Write-Warning $_.Exception.Message }
        try {
            $heartbeat = @{ collector_id = $state.id; host = $env:COMPUTERNAME; channels = $channels; status = $status; sent = [long]$state.sent; local_auth = [long]$state.local_auth } | ConvertTo-Json -Compress
            Invoke-RestMethod -Uri "$ApiUrl/api/v1/collectors/heartbeat" -Method Post -Headers @{Authorization="Bearer $apiKey"} -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($heartbeat)) -TimeoutSec 10 | Out-Null
        } catch { Write-Warning 'Heartbeat unavailable; the collector will retry.' }
        if (!$Once) { Start-Sleep -Seconds 5 }
    } while (!$Once)
} finally { $lock.Dispose() }
