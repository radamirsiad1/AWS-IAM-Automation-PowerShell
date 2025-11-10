<#
  provisioning.ps1  — macOS PowerShell 7+
  Robust version: tries AWS Tools cmdlets first, falls back to AWS CLI when a cmdlet
  isn't present on macOS.

  Prereqs:
    - AWS credentials configured (aws configure OR named profile via Initialize-AWSDefaultConfiguration)
    - AWS CLI installed (for fallbacks)
    - AWS PowerShell modules:
        Install-Module AWS.Tools.Common -Scope CurrentUser -Force
        Install-Module AWS.Tools.IdentityManagement -Scope CurrentUser -Force

  CSV expected at ~/Downloads/users.csv with headers:
    FirstName,LastName,UserName,Department,Action
#>

$ErrorActionPreference = 'Stop'
$ConfirmPreference     = 'None'

# --- toggles ---
$CreateLoginProfile = $false     # set $true to assign temp console password
$AddToDeptGroup     = $true
$CreatedByTag       = "ps-automation"

# --- logging ---
$LogFile = "$HOME/Downloads/provisioning_log.txt"
Start-Transcript -Path $LogFile -Append

# --- load module if available ---
try { Import-Module AWS.Tools.IdentityManagement -ErrorAction Stop } catch {}

# -------- Helper: test if a cmdlet exists --------
function Test-Cmd { param([string]$Name) !!(Get-Command $Name -ErrorAction SilentlyContinue) }

# -------- Helper: safe JSON run for AWS CLI --------
function Invoke-AwsJson {
  param([string]$Args)
  $json = & aws $Args 2>$null
  if ($LASTEXITCODE -eq 0 -and $json) { return (ConvertFrom-Json $json) }
  else { return $null }
}

# -------- Fallback “Get-” wrappers (cmdlet → CLI) --------
function Get-AttachedPoliciesForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMAttachedUserPolicies') {
    $r = Get-IAMAttachedUserPolicies -UserName $UserName -ErrorAction SilentlyContinue
    if ($r -and $r.AttachedPolicies) { return $r.AttachedPolicies }
    return $r
  } else {
    return (Invoke-AwsJson "iam list-attached-user-policies --user-name $UserName").AttachedPolicies
  }
}

function Get-InlinePoliciesForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMUserPolicies') {
    return Get-IAMUserPolicies -UserName $UserName -ErrorAction SilentlyContinue
  } else {
    return (Invoke-AwsJson "iam list-user-policies --user-name $UserName").PolicyNames
  }
}

function Get-GroupsForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMGroupsForUser') {
    $r = Get-IAMGroupsForUser -UserName $UserName -ErrorAction SilentlyContinue
    if ($r -and $r.Groups) { return $r.Groups }
    return $r
  } else {
    return (Invoke-AwsJson "iam list-groups-for-user --user-name $UserName").Groups
  }
}

function Get-AccessKeysForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMAccessKeysForUser') {
    $r = Get-IAMAccessKeysForUser -UserName $UserName -ErrorAction SilentlyContinue
    if ($r -and $r.AccessKeyMetadata) { return $r.AccessKeyMetadata }
    return $r
  } else {
    return (Invoke-AwsJson "iam list-access-keys --user-name $UserName").AccessKeyMetadata
  }
}

function Get-SSHPublicKeysForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMSSHPublicKeys') {
    $r = Get-IAMSSHPublicKeys -UserName $UserName -ErrorAction SilentlyContinue
    if ($r -and $r.SSHPublicKeys) { return $r.SSHPublicKeys }
    return $r
  } else {
    return (Invoke-AwsJson "iam list-ssh-public-keys --user-name $UserName").SSHPublicKeys
  }
}

function Get-SigningCertsForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMSigningCertificates') {
    $r = Get-IAMSigningCertificates -UserName $UserName -ErrorAction SilentlyContinue
    if ($r -and $r.Certificates) { return $r.Certificates }
    return $r
  } else {
    return (Invoke-AwsJson "iam list-signing-certificates --user-name $UserName").Certificates
  }
}

function Get-ServiceSpecificCredsForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMServiceSpecificCredentials') {
    $r = Get-IAMServiceSpecificCredentials -UserName $UserName -ErrorAction SilentlyContinue
    if ($r -and $r.ServiceSpecificCredentials) { return $r.ServiceSpecificCredentials }
    return $r
  } else {
    return (Invoke-AwsJson "iam list-service-specific-credentials --user-name $UserName").ServiceSpecificCredentials
  }
}

function Get-MFADevicesForUser {
  param([string]$UserName)
  if (Test-Cmd 'Get-IAMMFADevices') {
    $r = Get-IAMMFADevices -UserName $UserName -ErrorAction SilentlyContinue
    if ($r -and $r.MFADevices) { return $r.MFADevices }
    return $r
  } else {
    return (Invoke-AwsJson "iam list-mfa-devices --user-name $UserName").MFADevices
  }
}

# -------- misc helpers --------
function New-TempPassword {
  $chars = (48..57 + 65..90 + 97..122 + 35,36,37,38) | ForEach-Object {[char]$_}
  -join (1..16 | ForEach-Object { $chars | Get-Random })
}

# -------- load CSV --------
$csvPath = "$HOME/Downloads/users.csv"
if (!(Test-Path $csvPath)) { Write-Host "CSV not found at $csvPath"; Stop-Transcript; exit 1 }
$rows = Import-Csv -Path $csvPath
if (-not $rows -or $rows.Count -eq 0) { Write-Host "CSV empty."; Stop-Transcript; exit 1 }
Write-Host ("Loaded {0} user entries from CSV.`n" -f $rows.Count)

foreach ($r in $rows) {
  $FirstName  = ($r.FirstName  | ForEach-Object { $_.ToString().Trim() })
  $LastName   = ($r.LastName   | ForEach-Object { $_.ToString().Trim() })
  $UserName   = ($r.UserName   | ForEach-Object { $_.ToString().Trim() })
  $Department = ($r.Department | ForEach-Object { $_.ToString().Trim() })
  $Action     = ($r.Action     | ForEach-Object { $_.ToString().Trim() })

  if (-not $UserName -or -not $Action) { Write-Host "Skipping invalid entry (missing UserName or Action)."; continue }
  Write-Host ("Processing user: {0} ({1})" -f $UserName, $Action)

  switch ($Action.ToLower()) {

    'create' {
      try {
        $exists = try { Get-IAMUser -UserName $UserName -ErrorAction Stop } catch { $null }
        if (-not $exists) {
          New-IAMUser -UserName $UserName -Path ("/{0}/" -f $Department) `
            -Tags @(
              @{ Key="FirstName";  Value=$FirstName }
              @{ Key="LastName";   Value=$LastName  }
              @{ Key="Department"; Value=$Department}
              @{ Key="CreatedBy";  Value=$CreatedByTag }
            ) | Out-Null
          Write-Host ("Created user: {0}" -f $UserName)
        } else {
          Write-Host ("User already exists: {0}" -f $UserName)
        }

        if ($CreateLoginProfile) {
          try {
            $pwd = New-TempPassword
            New-IAMLoginProfile -UserName $UserName `
              -Password (ConvertTo-SecureString $pwd -AsPlainText -Force) `
              -PasswordResetRequired $true | Out-Null
            Write-Host ("Temp password for {0}: {1} (share securely)" -f $UserName, $pwd)
          } catch {
            if ($_.Exception.Message -notmatch 'EntityAlreadyExists') { throw }
            Write-Host ("Login profile already exists for {0}" -f $UserName)
          }
        }

        if ($AddToDeptGroup -and $Department) {
          try { Get-IAMGroup -GroupName $Department | Out-Null }
          catch { New-IAMGroup -GroupName $Department | Out-Null ; Write-Host ("Created group: {0}" -f $Department) }

          try {
            Add-IAMUserToGroup -GroupName $Department -UserName $UserName -ErrorAction Stop
            Write-Host ("Added {0} to group {1}" -f $UserName, $Department)
          } catch {
            if ($_.Exception.Message -notmatch 'EntityAlreadyExists') {
              Write-Host ("Could not add {0} to {1}: {2}" -f $UserName, $Department, $_.Exception.Message)
            }
          }
        }
      } catch {
        Write-Host ("Create failed for {0}: {1}" -f $UserName, $_.Exception.Message)
      }
    }

    'delete' {
      try {
        $exists = try { Get-IAMUser -UserName $UserName -ErrorAction Stop } catch { $null }
        if (-not $exists) { Write-Host ("{0} does not exist — skipping delete." -f $UserName); break }

        # 1) remove console login
        try { Remove-IAMLoginProfile -UserName $UserName -ErrorAction Stop } catch {}

        # 2) detach managed policies
        (Get-AttachedPoliciesForUser -UserName $UserName) | ForEach-Object {
          $arn = $_.PolicyArn ?? $_.Arn
          if ($arn) { Detach-IAMUserPolicy -UserName $UserName -PolicyArn $arn -ErrorAction SilentlyContinue }
        }

        # 3) delete inline policies
        (Get-InlinePoliciesForUser -UserName $UserName) | ForEach-Object {
          if ($_){ Remove-IAMUserPolicy -UserName $UserName -PolicyName $_ -ErrorAction SilentlyContinue }
        }

        # 4) remove from groups
        (Get-GroupsForUser -UserName $UserName) | ForEach-Object {
          $gname = $_.GroupName ?? $_
          if ($gname){ Remove-IAMUserFromGroup -GroupName $gname -UserName $UserName -ErrorAction SilentlyContinue }
        }

        # 5) delete access keys
        (Get-AccessKeysForUser -UserName $UserName) | ForEach-Object {
          if ($_.AccessKeyId){ Remove-IAMAccessKey -UserName $UserName -AccessKeyId $_.AccessKeyId -ErrorAction SilentlyContinue }
        }

        # 6) delete ssh keys
        (Get-SSHPublicKeysForUser -UserName $UserName) | ForEach-Object {
          if ($_.SSHPublicKeyId){ Remove-IAMSSHPublicKey -UserName $UserName -SSHPublicKeyId $_.SSHPublicKeyId -ErrorAction SilentlyContinue }
        }

        # 7) delete signing certs
        (Get-SigningCertsForUser -UserName $UserName) | ForEach-Object {
          if ($_.CertificateId){ Remove-IAMSigningCertificate -UserName $UserName -CertificateId $_.CertificateId -ErrorAction SilentlyContinue }
        }

        # 8) delete service-specific creds
        (Get-ServiceSpecificCredsForUser -UserName $UserName) | ForEach-Object {
          if ($_.ServiceSpecificCredentialId){
            Remove-IAMServiceSpecificCredential -UserName $UserName -ServiceSpecificCredentialId $_.ServiceSpecificCredentialId -ErrorAction SilentlyContinue
          }
        }

        # 9) deactivate MFA
        (Get-MFADevicesForUser -UserName $UserName) | ForEach-Object {
          if ($_.SerialNumber){ Deactivate-IAMMFADevice -UserName $UserName -SerialNumber $_.SerialNumber -ErrorAction SilentlyContinue }
        }

        # 10) permissions boundary (best-effort)
        try { Remove-IAMUserPermissionsBoundary -UserName $UserName -ErrorAction SilentlyContinue } catch {}

        # 11) delete user
        Remove-IAMUser -UserName $UserName -Force
        Write-Host ("Deleted user: {0}" -f $UserName)

      } catch {
        Write-Host ("Delete failed for {0}: {1}" -f $UserName, $_.Exception.Message)
      }
    }

    Default { Write-Host ("Invalid action for {0}. Must be Create or Delete." -f $UserName) }
  }
}

Write-Host "`nProvisioning run complete. Check AWS Console and provisioning_log.txt for results."
Stop-Transcript
