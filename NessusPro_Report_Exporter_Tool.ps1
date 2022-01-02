<# 
ScriptName:    NessusPro_Report_Exporter_Tool.ps1
Purpose:       Powershell script that use REST methods to obtain report automation. This script provides the convinience to download multiple types of reports(Scan completed reports only) based on nessus scan start date & time.
Date Modified: 2 Jan 2022

Comments:
Notes:      -Script must be run with ACL that has proxy access if external facing Nessus.io servers are targeted
            -Ensure execution policy is set to unrestricted (Requires Administrative ACL)

Credits:
    ScriptSource: NessusPro_v7_Report_Exporter_Tool.ps1
    Github:     https://github.com/Pwd9000-ML/NessusV7-Report-Export-PowerShell
    Created:    Sept 2018.

Script Requirements:
    -Ensure correct execution policy is set to run script. Administrative permission is required to Set-ExecutionPolicy.
    -Set-ExecutionPolicy Bypass

Future enhancements:
    -S.No for the scan completed list
    -Parmeter for custom id's or folder numbers
    -Exported file size check
    -Custom output path

#>
Write-Host ""

#------------------Allow Selfsign Cert + workaround force TLS 1.2 connections---------------------
add-type @"
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	public class TrustAllCertsPolicy : ICertificatePolicy {
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate,
			WebRequest request, int certificateProblem) {
				return true;
				}
	}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


#------------------Nessus Connection Details -----------------------------------------------------
switch(3){   #CUSTOMIZABLE_POINT:NESSUS_CONNECTION_SETTINS - You may cahnge this if the user needs to be prompted for Nessus details.
    1 {   
        #Nessus details to be given before executing the script. This is good when a script is designed to specific client. But becareful with the password being exposed
        $Baseurl = "https://localhost:8834"
        $Username = "nessus"
        $password = "password"
    }
    2 {   
        #Nessus URL & username to be hardcoded. Password will be provided manually to reduce the attack surface.
        $Baseurl = "https://localhost:8834"
        $Username = "nessus"
        $PasswordResponse = Read-Host "Enter Password" -AsSecureString
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordResponse))
    }

    3 {
        #Asking user for nessus ip, username & passwords
        $default = "https://localhost:8834"
        if (!($Baseurl = Read-Host "Enter Nessus Scanner URL + Port (e.g. https://NessusServerFQDN:8834) [$default]")) { $Baseurl = $default }
        
        $default = "nessus"
        if (!($Username = Read-Host "Enter login username (e.g. Administrator) [$default]")) { $Username = $default }

        $PasswordResponse = Read-Host "Enter Password" -AsSecureString
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordResponse))
    }
}

switch(1){ #CUSTOMIZABLE_POINT:NESSUS_REPORT_START_DATE - You may cahnge this if the user needs to be prompted for Start time and the no of hours.
    1 { 
        #Ask user for EPOCH & HOURS
        $default = [long] (Get-Date -Date ((Get-Date).ToUniversalTime()) -UFormat %s)
        if (!($epoch = [int64](Read-Host "Enter the date & time in EPOCH format or press ENTER to take the current timestamp (Ref: https://www.epochconverter.com/) [$default]"))) { $epoch = $default }

        $default = 8
        if (!($time_buffer = [int64](Read-Host "Enter the time buffer to collect the scan results (e.g. 8 to export the results started in last 8 hours) [$default]"))) { $time_buffer = $default }
    }

    2 { 
        #Ask user for no of HOURS
        $epoch = [long] (Get-Date -Date ((Get-Date).ToUniversalTime()) -UFormat %s)

        $default = 8
        if (!($time_buffer = [int64](Read-Host "Enter the time buffer to collect the scan results (e.g. 8 to export the results started in last 8 hours) [$default]"))) { $time_buffer = $default }
    }
    3 { 
        #Nessus details to be given before executing the script. This is to customize the Nessus scan report duration based on the scan start date
        $epoch = 1562518822#PWK  #1571134999
        $time_buffer = 8
  
        $epoch = 1571134999
        $time_buffer = 3200
    }
}

$ContentType = "application/json"
$POSTMethod = 'POST'
$GETMethod = 'GET'
#------------------Create Json Object--------------------------------------------------------------
$UserNameBody = convertto-json (New-Object PSObject -Property @{username = $username; password = $Password})

#------------------Create URI's--------------------------------------------------------------------
$SessionAPIurl = "/session"
$ScansAPIurl = "/scans"
$SessionUri = $baseurl + $SessionAPIurl
$ScansUri = $baseurl + $ScansAPIurl

#------------------Stage props to obtain session token (Parameters)--------------------------------
$session = @{
    Uri         = $SessionUri
    ContentType = $ContentType
    Method      = $POSTMethod
    Body        = $UserNameBody
}

#------------------Commit session props for token header X-cookie----------------------------------
$TokenResponse = Invoke-RestMethod @session
if ($TokenResponse) {
    $Header = @{"X-Cookie" = "token=" + $TokenResponse.token}
}
else { 
    Write-host ""
    Write-host "Error occured obtaining session token. Script Terminating... Please ensure Username and Password Correct." -ForegroundColor Red
    Start-Sleep -s 20
    Exit
}

#------------------Output completed scans----------------------------------------------------------
$Nessus_Scan_data = (Invoke-RestMethod -Uri $ScansUri -Headers $Header -Method $GETMethod -ContentType "application/json").scans

$Scanscompleted_obj = $Nessus_Scan_data | ? {($_.status -eq "completed") -and ($epoch -ge $_.creation_date) -and ((($epoch-$_.creation_date)/60/60) -lt $time_buffer)}
$Scansnotcompleted_obj = $Nessus_Scan_data | ? {($_.status -ne "completed") -and ($epoch -ge $_.creation_date) -and ((($epoch-$_.creation_date)/60/60) -lt $time_buffer)}

$Scanscompleted = $Scanscompleted_obj | Select-Object @{Name = "Scan Name"; Expression = {$_.Name}},
                @{Name = "Scan Status"; Expression = {$_.Status}},
                @{Name = "Id"; Expression = {$_.id}},
                @{Name = "Scan Start Date"; Expression = {[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($_.creation_date))}},
                @{Name = "Scan Completed Date"; Expression = {[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($_.last_modification_date))}},
                @{Name = "Scan Time(M)"; Expression = {[int64](($_.last_modification_date-$_.creation_date)/60)}} | Format-Table -AutoSize

$Scansnotcompleted = $Scansnotcompleted_obj | Select-Object @{Name = "Scan Name"; Expression = {$_.Name}},
                @{Name = "Scan Status"; Expression = {$_.Status}},
                @{Name = "Id"; Expression = {$_.id}},
                @{Name = "Scan Start Date"; Expression = {[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($_.creation_date))}},
                @{Name = "Scan Completed Date"; Expression = {[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($_.last_modification_date))}},
                @{Name = "Scan Time(M)"; Expression = {[int64](($_.last_modification_date-$_.creation_date)/60)}} | Format-Table -AutoSize


$Any_scans_completed = $false
if ($Scanscompleted -eq $null) {
    Write-Host "------------------------------------------------------" -ForegroundColor yellow
    Write-Host "-There are no scans completed hence can't be exported-" -ForegroundColor yellow
    Write-Host "------------------------------------------------------" -ForegroundColor yellow
} else { 
    Write-Host "-------------------------------------------------------" -ForegroundColor Green
    Write-Host "-The following Scans are Completed and can be exported-" -ForegroundColor Green
    Write-Host "-------------------------------------------------------" -ForegroundColor Green
    $Any_scans_completed = $true
    $Scanscompleted
}

if ($Scansnotcompleted -eq $null) {
    Write-Host "-------------------------------------------------" -ForegroundColor yellow
    Write-Host "-There are no scans that are pending/have issues-" -ForegroundColor yellow
    Write-Host "-------------------------------------------------" -ForegroundColor yellow
} else { 
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Red
    Write-Host "-The following Scans have issues and cannot be exported autonomously-" -ForegroundColor Red
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Red
    $Scansnotcompleted
}

#------------------Exit the script execution if no reports ready to fetch ----------------------------
if ($Any_scans_completed -eq $false) { exit }

#------------------Export Completed Scans (Y/N)----------------------------------------------------
Write-Host "------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "-This script can download 4 different report formats for each scan-" -ForegroundColor DarkGray
Write-Host "- Supported Formats: nessus OR db OR csv OR HTML or all" -ForegroundColor DarkGray
Write-Host "`nNote: HTML report will generate 3 different HTML reports (Vulnerabilities by HOST, Plugin, Complinace)" -ForegroundColor DarkGray
Write-Host "------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""


#------------------REPORT Format selection------------------------------------------------------------
$default = "all"
if (!($answerexport = Read-Host "Enter selection [$default]")) { $answerexport = $default }
switch($answerexport.toupper()) {
    "ALL" { $report_type = 1..7}
    "NESSUS" { $report_type = 1}
    "DB" { $report_type = 2}
    "CSV" { $report_type = 3}
    "HTML" { $report_type = 4..7}
    default { $report_type = 0}
}

#------------------ Check if the given input is valid ------------------------------------------------
If ($report_type -eq 0) {
    Write-Host "`nInvalid input. This script is going to terminate" -ForegroundColor Red
    exit
} 

#------------------Nessus DB Password Settings -------------------------------------------------------
switch(2){ #CUSTOMIZABLE_POINT:NESSUS_DB_PASSWORD - You may select if the user needs to be prompted for Nessus DB password.
    1 {
        $nessus_db_password = "my_db_password"
    }

    2 {
        if($report_type -contains 7) {
            $default = "my_db_password"
            if (!($nessus_db_password = Read-Host "`nSelected any password for Nessus_DB format [$default]")) { $nessus_db_password = $default }

        }
    }
}

$startMs = Get-Date
$continue = $True

#------------------POST Export Requests------------------------------------------------------------
$Count = 1
$Scanscompleted_obj | select-object id, name |
   % { 
      
       $ScanName = $_.name
       $Scanid = $_.id
       $ScanName_File = $ScanName

       #CUSTOMIZABLE_POINT:REPORT_NAME_ESCAPING - You may add multiple entries to replace special symbols that needs to be replaced on file name.
       $ScanName_File =  $ScanName_File -replace '\[', '('
       $ScanName_File =  $ScanName_File -replace '\]', ')'
       $ScanName_File =  $ScanName_File -replace ' ', '_'

       Write-Host "`nWorking on Scan $Count : $ScanName" -ForegroundColor Magenta
       foreach ($i in $report_type) {
            switch($i)
            {
                #To add more formats, you may refer to "https://<NESSUS_IP>:<PORT>/api#/resources/scans/export-formats"
               1 {
                    $Format = ".nessus"
                    $Format_str = "$i.Nessus (XML)"
                    $ExportBody = "{`"format`":`"nessus`"}"
                }
               
               2 {
                    $Format = ".db"
                    $Format_str = "$i.Nessus DB (Password: $nessus_db_password)"
                    $ExportBody = "{`"format`":`"db`",`"password`":`"$nessus_db_password`"}"
                }               
                
               3 {
                    $Format = ".csv"
                    $Format_str = "$i.CSV"
                    switch(2) {     #CUSTOMIZABLE_POINT:REPORT_OUTPUT_SECTIONS - You may add multiple fields to be exported.
                        1{
                            $ExportBody = "{`"format`":`"csv`"}"
                        }
                        2{
                            $ExportBody = "{`"format`":`"csv`",`"template_id`":`"`",`"reportContents`":{`"csvColumns`":{`"id`":true,`"cve`":true,`"cvss`":true,`"risk`":true,`"hostname`":true,`"protocol`":true,`"port`":true,`"plugin_name`":true,`"synopsis`":true,`"description`":true,`"solution`":true,`"see_also`":true,`"plugin_output`":true,`"stig_severity`":true,`"cvss3_base_score`":true,`"cvss_temporal_score`":true,`"cvss3_temporal_score`":true,`"risk_factor`":true,`"references`":true,`"plugin_information`":true,`"exploitable_with`":true}},`"extraFilters`":{`"host_ids`":[],`"plugin_ids`":[]}}"
                        }
                    }
                }
               
               4{
                    switch(1) {     #CUSTOMIZABLE_POINT:
                        1{
                            $Format = "_(Plugins).html"
                            $Format_str = "$i.HTML (Sort by Plugins)"
                            $ExportBody = "{`"format`":`"html`",`"chapters`":`"vuln_by_plugin`"}"
                        }

                        2{
                            $Format = "_(Plugins+Complinace).html"
                            $Format_str = "$i.HTML (Sort by Plugins with compliances)"
                            $ExportBody = "{`"format`":`"html`",`"chapters`":`"vuln_by_plugin,compliance`"}"
                        }
                    }
                }
               5{
                    switch(1) {     #CUSTOMIZABLE_POINT:
                        1{
                            $Format = "_(Host).html"
                            $Format_str = "$i.HTML (Sort by Host)"
                            $ExportBody = "{`"format`":`"html`",`"chapters`":`"vuln_by_host`"}"
                        }

                        2{
                            $Format = "_(Host+Complinace).html"
                            $Format_str = "$i.HTML (Sort by Host with compliances)"
                            $ExportBody = "{`"format`":`"html`",`"chapters`":`"vuln_by_host,compliance`"}"
                        }
                    }
                }
               6{
                    switch(1) {     #CUSTOMIZABLE_POINT:
                        1{
                           $Format = "_(compliance_Host).html"
                           $Format_str = "$i.HTML (compliance with Host details)"
                           $ExportBody = "{`"format`":`"html`",`"chapters`":`"vuln_by_host,compliance`"}"
                        }

                        2{
                           $Format = "_(compliance_Only).html"
                           $Format_str = "$i.HTML (compliance Only)"
                           $ExportBody = "{`"format`":`"html`",`"chapters`":`"compliance`"}"
                        }
                    }
                 }
               7{
                    switch(1) {     #CUSTOMIZABLE_POINT:
                        1{
                            #To be corrected based on template id's
                            $Format = "_(Detailed).html"
                            $Format_str = "$i.HTML (Contains Host and Plugins along with the compliance)"
                            $ExportBody = "{`"format`":`"html`",`"chapters`":`"vuln_by_host,vuln_by_plugin,compliance`"}"
                        }

                        2{
                            $Format = "_(Detailed).html"
                            $Format_str = "$i.HTML (Contains Host and Plugins along with the compliance (if any))"
                            $ExportBody = "{`"format`":`"html`",`"chapters`":`"vuln_by_host,vuln_by_plugin,compliance`"}"
                        }
                    }
                }
            }

            switch(2) {  #CUSTOMIZABLE_POINT:    This point use the Nessus Web UI export with Limit=2500 or without the parameter.
                
                1{
                    #This is the Nessus Web UI call with limit parameter
                    $Export_Uri         = "$ScansUri" + "/$Scanid/export?limit=2500"
                }

                2{ 
                    #This is the usual way of Nessus API call
                    $Export_Uri         = "$ScansUri" + "/$Scanid/export"
                }
            }

            $Exportfile = @{
                Uri         = $Export_Uri
                ContentType = $ContentType
                Headers     = $Header
                Method      = $POSTMethod
                Body        = $ExportBody
            }

            Start-Sleep -s 1
            try{

            try{
                $Export_file = Invoke-RestMethod @Exportfile
            } catch { #------------------Check if the API Token expired -------------------------------------------------

                Write-Warning "API token expired. Getting a new token from the previously provided credentials"
               
                #------------------Commit session props for token header X-cookie----------------------------------
                $TokenResponse = Invoke-RestMethod @session
                if ($TokenResponse) {
                    $Header = @{"X-Cookie" = "token=" + $TokenResponse.token}
                    Write-Warning "valid token received"
                    $Export_file = Invoke-RestMethod @Exportfile
                }
                else { 
                    Write-host ""
                    Write-host "Error occured obtaining session token. Script Terminating..." -ForegroundColor Red
                    Start-Sleep -s 20
                    Exit
                }
            }

            Write-Host "`tReport Format: '$Format_str'" -ForegroundColor DarkCyan
            Write-Host "`t`tScan $Count : Step 1 - Requesting for file to download"
            switch(2) {     #CUSTOMIZABLE_POINT:NESSUS_INTERACTION_API-WEBUI - You may select the way API could request Nessus for report download.
                
                1{  #This is as per the API documentation (unlike Nessus Web UI)
                    $file = $Export_file.file
                    $StatusUri = "$ScansUri" + "/$Scanid/export/" + "$file" + "/status"
                    $DownloadUri = "$ScansUri" + "/$Scanid/export/" + "$file" + "/download"
                }
                
                2{  #This is the way Nessus Web UI use
                    
                    $token = $Export_file.token
                    $StatusUri = "$baseurl" + "/tokens/" + $token + "/status"
                    $DownloadUri = "$baseurl" + "/tokens/" + $token +  "/download"
                }
            }

            Write-Host "`t`tScan $Count : Step 2 - Waiting for Nessus scan to be ready" -NoNewline
            $loading_banner = $true
            while(1) {
                Start-Sleep -s 2
                $report_status = Invoke-RestMethod -Uri "$StatusUri" -ContentType $ContentType -Headers $Header -Method $GETMethod

                Write-Verbose "$report_status"
                
                #Check if there is any error in the status. if yes, exit the program to avoid the infinite loops
                if($report_status.error -ne $null){
                    Write-Host "`n Error received during the scan status API call. Error is: ($report_status.error)" -ForegroundColor Red
                    Write-Host "Script going to terminate." -ForegroundColor Red
                    exit
                }

                $report_status.status | 
                    % {
                    Write-Verbose "$_"
                    If ($_ -ne "ready") {
                        if ($loading_banner){
                            Write-Host "`tLoading.." -ForegroundColor Red -NoNewline
                            $loading_banner = $false
                        }
                        Write-Host "." -ForegroundColor Red -NoNewline
                        Write-Verbose $_
                    } else { break }
                }
            }
            Write-Host "`tReady." -ForegroundColor Green -NoNewline

            Write-Host "`n`t`tScan $Count : Step 3 - Downloading the report"
            Start-Sleep -s 1
            Invoke-WebRequest -Uri "$DownloadUri" -ContentType $ContentType -Headers $Header -Method $GETMethod -OutFile "C:\Temp\$ScanName_File$format"                 
            Write-Host "`t`tScan $Count : Step 4 - Operation completed. File name: ""C:\Temp\$ScanName_File$format"""
            } catch { 
                Write-Host "`nError occured during the export operation. You may generate this report '$Format_str' manually."  -ForegroundColor Red
                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__   -ForegroundColor yellow
                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -ForegroundColor yellow
            }
        }
        $Count = $Count + 1
    }
$endMs = Get-Date
Write-Host "`nAll reports downloaded. Total duration for generating the above reports is "  -ForegroundColor green -NoNewline 
Write-Host "$($endMs - $startMs)" -ForegroundColor cyan 
exit
                 
#------------------Script END----------------------------------------------------------------------
