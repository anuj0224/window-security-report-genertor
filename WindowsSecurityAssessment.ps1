
<# 
Windows Security Assessment Report Generator
Generates HTML dashboard and PDF report using Edge/Chrome headless mode
#>

param(
    [string]$OutputDir = ".\Assessment"
)

$ErrorActionPreference = "SilentlyContinue"

# -------------------------------
# Create folders
# -------------------------------
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$EvidenceDir = Join-Path $OutputDir "Evidence"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

# -------------------------------
# Helper Functions
# -------------------------------
function Save-Evidence {
    param(
        [string]$Name,
        [object]$Data
    )
    $Data | Out-File -Encoding UTF8 (Join-Path $EvidenceDir "$Name.txt")
}

function Get-RiskScore {
    param(
        $Defender,
        $ListeningPorts,
        $Admins
    )

    $score = 100
    $findings = @()

    if (-not $Defender.RealTimeProtectionEnabled) {
        $score -= 30
        $findings += "Real-time protection disabled"
    }

    if ($ListeningPorts.LocalPort -contains 3306) {
        $score -= 4
        $findings += "MySQL exposed"
    }

    if ($ListeningPorts.LocalPort -contains 5432) {
        $score -= 4
        $findings += "PostgreSQL exposed"
    }

    if ($Admins.Count -gt 3) {
        $score -= 10
        $findings += "Multiple administrator accounts"
    }

    [PSCustomObject]@{
        Score = $score
        Findings = $findings
    }
}

# -------------------------------
# Collect Data
# -------------------------------

$Computer = Get-CimInstance Win32_ComputerSystem
$OS = Get-CimInstance Win32_OperatingSystem
$BIOS = Get-CimInstance Win32_BIOS

$Users = net user
$Admins = net localgroup administrators

$Defender = Get-MpComputerStatus

$ListeningPorts = Get-NetTCPConnection -State Listen |
    Sort-Object LocalPort

$EstablishedConnections = Get-NetTCPConnection -State Established

$Services = Get-Service |
    Where-Object {$_.Status -eq 'Running'} |
    Sort-Object DisplayName

$Startup = Get-CimInstance Win32_StartupCommand

$Tasks = Get-ScheduledTask |
    Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'}

$Shares = net share

# Save raw evidence
Save-Evidence "users" $Users
Save-Evidence "administrators" $Admins
Save-Evidence "services" $Services
Save-Evidence "startup" $Startup
Save-Evidence "scheduled_tasks" $Tasks
Save-Evidence "listening_ports" $ListeningPorts
Save-Evidence "established_connections" $EstablishedConnections
Save-Evidence "shares" $Shares

# -------------------------------
# Risk Assessment
# -------------------------------

$Risk = Get-RiskScore `
    -Defender $Defender `
    -ListeningPorts $ListeningPorts `
    -Admins ($Admins | Select-Object -Skip 6)

if ($Risk.Score -ge 90) {
    $RiskLevel = "LOW"
}
elseif ($Risk.Score -ge 70) {
    $RiskLevel = "MEDIUM"
}
else {
    $RiskLevel = "HIGH"
}

# -------------------------------
# HTML Styling
# -------------------------------

$Css = @"
<style>
body{
font-family:Segoe UI,Arial;
background:#f4f7fb;
margin:0;
padding:0;
}
.header{
background:#1f2937;
color:white;
padding:30px;
}
.container{
padding:20px;
}
.card{
background:white;
padding:20px;
margin-bottom:20px;
border-radius:10px;
box-shadow:0 2px 6px rgba(0,0,0,.1);
}
.score{
font-size:48px;
font-weight:bold;
}
.low{color:green;}
.medium{color:orange;}
.high{color:red;}
table{
width:100%;
border-collapse:collapse;
}
th{
background:#1f2937;
color:white;
padding:8px;
}
td{
padding:8px;
border-bottom:1px solid #ddd;
}
.badge{
padding:6px 10px;
border-radius:6px;
background:#e5e7eb;
}
.footer{
text-align:center;
padding:20px;
font-size:12px;
color:#666;
}
</style>
"@

# -------------------------------
# HTML Sections
# -------------------------------

$PortRows = ($ListeningPorts |
    Select-Object LocalAddress,LocalPort,OwningProcess |
    ConvertTo-Html -Fragment)

$ServiceRows = ($Services |
    Select-Object DisplayName,Name |
    ConvertTo-Html -Fragment)

$StartupRows = ($Startup |
    Select-Object Name,Command |
    ConvertTo-Html -Fragment)

$TaskRows = ($Tasks |
    Select-Object TaskName,TaskPath |
    ConvertTo-Html -Fragment)

$ConnRows = ($EstablishedConnections |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort |
    ConvertTo-Html -Fragment)

$Recommendations = @()

if ($ListeningPorts.LocalPort -contains 3306) {
    $Recommendations += "<li>Restrict MySQL to localhost if remote access is not required.</li>"
}

if ($ListeningPorts.LocalPort -contains 5432) {
    $Recommendations += "<li>Restrict PostgreSQL to localhost if remote access is not required.</li>"
}

if ($Defender.FullScanAge -gt 30) {
    $Recommendations += "<li>Run a full Microsoft Defender scan.</li>"
}

if ($Recommendations.Count -eq 0) {
    $Recommendations += "<li>No major recommendations.</li>"
}

$Html = @"
<html>
<head>
<title>Windows Security Assessment</title>
$Css
</head>
<body>

<div class='header'>
<h1>Windows Security Assessment Report</h1>
<p>Generated: $(Get-Date)</p>
</div>

<div class='container'>

<div class='card'>
<h2>Executive Summary</h2>
<div class='score'>$($Risk.Score)/100</div>
<h3 class='$(($RiskLevel).ToLower())'>Risk Level: $RiskLevel</h3>
</div>

<div class='card'>
<h2>System Information</h2>
<table>
<tr><td>Computer Name</td><td>$($Computer.Name)</td></tr>
<tr><td>Manufacturer</td><td>$($Computer.Manufacturer)</td></tr>
<tr><td>Model</td><td>$($Computer.Model)</td></tr>
<tr><td>Operating System</td><td>$($OS.Caption)</td></tr>
<tr><td>Version</td><td>$($OS.Version)</td></tr>
<tr><td>BIOS</td><td>$($BIOS.SMBIOSBIOSVersion)</td></tr>
</table>
</div>

<div class='card'>
<h2>Microsoft Defender Status</h2>
<table>
<tr><td>Enabled</td><td>$($Defender.AntivirusEnabled)</td></tr>
<tr><td>Real-Time Protection</td><td>$($Defender.RealTimeProtectionEnabled)</td></tr>
<tr><td>Quick Scan Age</td><td>$($Defender.QuickScanAge)</td></tr>
<tr><td>Full Scan Age</td><td>$($Defender.FullScanAge)</td></tr>
</table>
</div>

<div class='card'>
<h2>Listening Ports</h2>
$PortRows
</div>

<div class='card'>
<h2>Established Connections</h2>
$ConnRows
</div>

<div class='card'>
<h2>Running Services</h2>
$ServiceRows
</div>

<div class='card'>
<h2>Startup Programs</h2>
$StartupRows
</div>

<div class='card'>
<h2>Scheduled Tasks</h2>
$TaskRows
</div>

<div class='card'>
<h2>Recommendations</h2>
<ul>
$($Recommendations -join "`n")
</ul>
</div>

</div>

<div class='footer'>
Generated by Windows Security Assessment Script
</div>

</body>
</html>
"@

# -------------------------------
# Save HTML
# -------------------------------

$HtmlPath = Join-Path $OutputDir "SecurityAssessment.html"
$Html | Set-Content -Encoding UTF8 $HtmlPath

# -------------------------------
# PDF Export
# -------------------------------

$PdfPath = Join-Path $OutputDir "SecurityAssessment.pdf"

$Edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
$Chrome = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"

if (Test-Path $Edge) {
    & $Edge --headless --disable-gpu --print-to-pdf="$PdfPath" "$HtmlPath"
}
elseif (Test-Path $Chrome) {
    & $Chrome --headless --disable-gpu --print-to-pdf="$PdfPath" "$HtmlPath"
}

Write-Host ""
Write-Host "Assessment completed."
Write-Host "HTML : $HtmlPath"
Write-Host "PDF  : $PdfPath"
Write-Host "Evidence Folder : $EvidenceDir"
