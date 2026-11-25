<#
.SYNOPSIS
    Script automatizado de compilación multi-arquitectura para NFC Bridge Driver (Windows Service).
    Genera binarios silenciosos (#![windows_subsystem = "windows"]) para:
    - x64 (x86_64)
    - x86 (32 bits)
    - arm64 (aarch64)
    - Sumas de verificación SHA-256 (.sha256)
#>

param(
    [string]$Version = "",
    [switch]$SkipArm64 = $false,
    [switch]$SkipX86 = $false
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DriverRepoDir = Resolve-Path (Join-Path $ScriptDir "..")
$DistDir = Join-Path $DriverRepoDir "dist"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $cargoRaw = Get-Content (Join-Path $DriverRepoDir "Cargo.toml") -Raw -Encoding UTF8
    if ($cargoRaw -match '(?m)^version\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    } else {
        $Version = "0.1.1"
    }
}

$gitSha = try { (git -C $DriverRepoDir rev-parse --short HEAD 2>$null).Trim() } catch { "nogit" }
$gitRev = try { (git -C $DriverRepoDir rev-list --count HEAD 2>$null).Trim() } catch { "0" }
if (-not $env:NFC_BRIDGE_BUILD_ID) {
    $env:NFC_BRIDGE_BUILD_ID = "d$gitRev-$gitSha-$(Get-Date -Format 'yyMMddHHmmss')"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    NFC BRIDGE DRIVER - BUILD v$Version ($($env:NFC_BRIDGE_BUILD_ID))" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Repositorio Driver:   $DriverRepoDir"
Write-Host "Directorio de Salida: $DistDir"
Write-Host ""

if (Test-Path $DistDir) {
    Remove-Item -Path $DistDir -Recurse -Force
}
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

function Generate-Checksum {
    param([string]$FilePath)
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    $fileName = Split-Path -Leaf $FilePath
    $checksumContent = "$hash *$fileName`n"
    $checksumFile = "$FilePath.sha256"
    [System.IO.File]::WriteAllText($checksumFile, $checksumContent)
    return "$hash *$fileName"
}

$checksumList = @()

# -------------------------------------------------------------
# 1. Compilación Estándar x64 (Release)
# -------------------------------------------------------------
Write-Host "`n[1/3] Compilando Driver x64 (Windows 64-bit)..." -ForegroundColor Green
Set-Location $DriverRepoDir
cargo build --release

$driverX64Src = Join-Path $DriverRepoDir "target\release\nfc-bridge-driver.exe"
$driverX64Dst = Join-Path $DistDir "nfc-bridge-driver-$Version-x64.exe"
Copy-Item $driverX64Src $driverX64Dst -Force
$checksumList += Generate-Checksum $driverX64Dst
Write-Host "  -> Creado: $(Split-Path -Leaf $driverX64Dst) ($( [math]::Round((Get-Item $driverX64Dst).Length / 1MB, 2) ) MB)"

# -------------------------------------------------------------
# 2. Compilación x86 (32 bits)
# -------------------------------------------------------------
if (-not $SkipX86) {
    Write-Host "`n[2/3] Intentando compilar Driver x86 (32 bits)..." -ForegroundColor Green
    $x86Candidates = @("i686-pc-windows-msvc", "i686-pc-windows-gnu")
    $installedTargets = rustup target list --installed
    $x86Built = $false

    foreach ($t in $x86Candidates) {
        if ($installedTargets -contains $t) {
            try {
                cargo build --release --target $t
                $src = Join-Path $DriverRepoDir "target\$t\release\nfc-bridge-driver.exe"
                if (Test-Path $src) {
                    $dst = Join-Path $DistDir "nfc-bridge-driver-$Version-x86.exe"
                    Copy-Item $src $dst -Force
                    $checksumList += Generate-Checksum $dst
                    Write-Host "  -> Creado ($t): $(Split-Path -Leaf $dst)"
                    $x86Built = $true
                    break
                }
            } catch {
                Write-Host "  [Aviso] Falló compilación x86 con $t (faltan librerías C/C++ x86 en el sistema)." -ForegroundColor Yellow
            }
        }
    }
    if (-not $x86Built) {
        Write-Host "  [Info] Para compilar x86 localmente instala el componente C++ x86 en Visual Studio Installer o usa GitHub Actions." -ForegroundColor Yellow
    }
}

# -------------------------------------------------------------
# 3. Compilación ARM64 (Windows en Snapdragon / Surface ARM)
# -------------------------------------------------------------
if (-not $SkipArm64) {
    Write-Host "`n[3/3] Intentando compilar Driver ARM64 (aarch64)..." -ForegroundColor Green
    $armTarget = "aarch64-pc-windows-msvc"
    $installedTargets = rustup target list --installed
    $armBuilt = $false

    if ($installedTargets -contains $armTarget) {
        try {
            cargo build --release --target $armTarget
            $src = Join-Path $DriverRepoDir "target\$armTarget\release\nfc-bridge-driver.exe"
            if (Test-Path $src) {
                $dst = Join-Path $DistDir "nfc-bridge-driver-$Version-arm64.exe"
                Copy-Item $src $dst -Force
                $checksumList += Generate-Checksum $dst
                Write-Host "  -> Creado: $(Split-Path -Leaf $dst)"
                $armBuilt = $true
            }
        } catch {
            Write-Host "  [Aviso] Falló compilación ARM64 (faltan librerías C++ ARM64 en Visual Studio Installer)." -ForegroundColor Yellow
        }
    }
    if (-not $armBuilt) {
        Write-Host "  [Info] Para compilar ARM64 localmente instala 'MSVC C++ ARM64 build tools' en Visual Studio Installer o usa GitHub Actions." -ForegroundColor Yellow
    }
}

# Guardar catálogo consolidado SHA256SUMS.txt
$sha256SumsFile = Join-Path $DistDir "SHA256SUMS.txt"
[System.IO.File]::WriteAllLines($sha256SumsFile, $checksumList)
Write-Host "`nChecksums SHA-256 consolidados guardados en: $(Split-Path -Leaf $sha256SumsFile)" -ForegroundColor Cyan

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  ¡COMPILACIÓN DE NFC BRIDGE DRIVER FINALIZADA!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Get-ChildItem $DistDir | Select-Object Name, Length | Format-Table -AutoSize
