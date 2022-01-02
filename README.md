# NessusPro - Report Exporter Tool (Powershell)

## Notes

**ScriptName:** NessusPro_Report_Exporter_Tool.ps1  
**Purpose:**    Powershell script that use REST methods to obtain report automation. This script provides the convinience to download multiple types of reports(Scan completed reports only) based on nessus scan start date & time.  
**Modified:**    Jan 2022  

**Credits:**    This script is prepared using another [github repo](https://github.com/Pwd9000-ML/NessusV7-Report-Export-PowerShell). Special thanks to [Pwd9000](https://github.com/Pwd9000-ML).

## Description  

A PowerShell script which will allow the user to connect to any Nessus Server (IO) Or (Pro V7 (tested on v10)) URL + Port and interact with the Nessus API to obtain information on scan reports.  

The user will be able to Export reports in a format of their choice e.g. nessus(XML), nessus database file, CSV, HTML(4 format types) or all the 4 report formats in one go.  

Reports will be stored on the local system under the path of `C:\Temp\`

## Usecase  

When we have to run multiple Nessus individualy (for 30 servers, 30 different scans), the report collection will be time taking. This script provides the ability to export the completed Nessus scan reports (based on the timestamps and buffer duration) with different formats in one shot.

## Features  
- This script can download multiple report formats on one go. 4 different customizations of HTML formats are available.  
- Default input is provided for few fields. This is indicated in `[ ]`. Just press enter without any input to take the default value as input. This helps user experienc when using the semi-customized script for similar project/cutomer.
- Customizable with hardcoded input or dynamic input. Designed with the intention of using different customized scripts for differnt customers.  
- `Loading...` text with dots will be displayed to indicate the Nessus Server status is not yet ready to download the huge reports. The status will be checked every two seconds and a `.` will be displayed for each status call. Refer to the `Powershell Console I/O` screenshots in this page.
- Verbose Nessus export for selected report formats and inline report status for good user experience.  
- API session timeouts are handled to resume the session from previously provided credentials. This helps when downloading a bunch of reports over night.  
- If any error occured during the export, error details with the report name will be displyed. User may download the particular report manually.  
- Scan time can be provided as an input, which provides the ability to export the Nessus scan that ran a long time ago.  
-	Nessus scan names with the special symbols like `[ ] whitespace` will be replaced with `_` to avoid file save or nessus import issues.  
- Total duation took to export the reports will be displayed after completing the Export operation. This helps to plan the user to export the periodic Nessus scans report.  


## Usage
  
This script is modified with the intentions of customizing the script for different client. So based on the settings you selected, the user will be prompted for the input when the script is run:  

**Login Details:**  
- Enter a full Nessus Scanner URL incl port (e.g. <https://NessusServerFQDN:8834> ). Press enter without any input to select nessus default port on local instance.  
- Enter a valid Username that has access to the nessus scanner URL provided.  
- Enter a valid Password to the corresponding Username provided.  

**Report Timestamp Details:**  
- Enter the date & time in EPOCH format. You may refer to https://www.epochconverter.com to get the timestamp in your custom requirement or press enter to select the current time as the baseline.  
- Enter the time buffer to collect the scan results. You may type 8 to export the results started in last 8 hours).  

**Report types:**  
- Enter the report type when prompted. Supported Formats: nessus OR db OR csv OR HTML or all  
- Enter any password for Nessus_DB format (only if the DB or ALL option selected).  

**Selecting the report time:**  
This script takes the `EPOCH` as the end point and the `Buffer Time` as the starting point. You may use online EPOCH converter https://www.epochconverter.com/ to convert the human readable time format to EPOCH or UNIX timestamp.  
- **Time calculation:** 
    ```` 
    EPOCH Timestamp(End point)  <----------------->  Buffer Time in Hrs (Starting point)
    ````

Example with different cases are given below for your reference:  
 - **Use case 1:** Export the scan results from past 24 hours
   -  Enter the date & time in EPOCH format:`    `  (just press enter to take the current timestamp as the end time)
   -  Enter the time buffer: `24`  
 - **Use case 2:** Export the results of scans started on `1 Jan 2022 10:00 AM to 6:00 PM` (Sameday) 
   -  Enter the date & time in EPOCH format:`1641060000` <**EPOCH(January 1, 2022 6:00 PM)** as the end time>
   -  Enter the time buffer: `8` <8 hrs buffer as the start time which is January 1, 2022 10:00 AM>
 - **Use case 3:** Export the results of scans started on `1 Jan 2022 10:00 AM to 5 Jan 2022 10:00 AM` (Sameday) 
   -  Enter the date & time in EPOCH format:`1641376800` <**EPOCH(January 5, 2022 10:00 AM
)** as the end time>
   -  Enter the time buffer: `96` <96 hrs buffer as the start time which is January 1, 2022 10:00 AM>
  

**Usage Notes/Limitations:**  
 - The scan time comparisions will be calculated based on the Nessus scan start time, because we can't guess the scan end time. 
 - Nessus scan start time later than the `EPOCH` time will be ignored. The script is modified intentionally to avoid the after certain period.  
 - This script can only fetch the **latest Nessus scan results** from the Nessus scan history. If a scan contains multiple history entries, the old entries will be ignored (Nessus API limitation).  


## Customizing the script:  

The script is modified with the intention to customize based on the project requirement. Which means,  

**#CUSTOMIZABLE_POINT:NESSUS_CONNECTION_SETTINS**
- **Mode-1:** You can hardcode the nessus details including the password (only suitable for personal setup for testing. Not advised in realtime nessus setup)  
- **Mode-2:** You can hardcode the nessus url and username but not the password. Password needs to be entered manually to avoid the password being exposed.  
- **Mode-3:** Prompt the user for Nessus URL, Nessus Username and associated Nessus Password.  

**#CUSTOMIZABLE_POINT:NESSUS_REPORT_START_DATE**
- **Mode-1:** Get the timestamp and the time buffer from the user  
- **Mode-2:** Hardcode the timestamp of any date & time but ask the user for time buffer  
- **Mode-3:** Hardcode the timestamp of any date & time and the time buffer  
  
**#CUSTOMIZABLE_POINT:NESSUS_DB_PASSWORD**
- **Mode-1:** Hardcode the Nessus DB password  
- **Mode-2:** Prompt the user for Nessus DB password  

**More sections:**  
You may explore the following section on your own and customize as per your requirement.
- #CUSTOMIZABLE_POINT:REPORT_OUTPUT_SECTIONS  
- #CUSTOMIZABLE_POINT:
- #CUSTOMIZABLE_POINT:NESSUS_INTERACTION_API-WEBUI

**Tips to customize Nessus Report Parameters:**  
Sometimes, you may need to select the custom format with few fields enabled or disabled. Or you may need to use the same script for upcoming versions of Nessus professional. In this case, you may need to know how to update the API request.

- Fetch the JSON response from the Nessus Web UI. You may refer the below screenshot to fetch the json request body.  
- Add the character \` in front of " for escaping them in powershell as special character. Replace " with \`" for this.  
- Update them in the powershell script. Make sure the given text is enclosed in "double quotes".  

- **Same Input & Output**  
  - Sample Input: `{"format":"nessus"}`  
  - Replace " with \`": ```` {`"format`":`"nessus`"} ````  
  - Enclose in "double quotes": ```` "{`"format`":`"nessus`"}" ````  

- **Screenshot** showing the fetching of json request body:  
  <kbd>![alt text](https://github.com/V9Y1nf0S3C/NessusPro-Report-Exporter-Tool/blob/main/Screenshots/Chrome_Developer_Options.png?raw=true)</kbd>  


## Troubleshooting the script:  
  
You may proxy the script to troubleshoot the script with your custom requirement. The below details contains some info on using Burp suite as a proxy to check the requests and responses.

**1.Proxy Connection details:**   
Nessus Connection is at 127.0.0.1:8834  
Burp Suite proxy listener: 127.0.0.1:8080  

**2.Traffic Flow:**  
Powershell  ------>  Burp Proxy (https://127.0.0.1:8080)  ------>  Nessus (https://127.0.0.1:8834)

**3.Configuration:**  
Setup the Burp proxy to listen on Port 8080 and redirect the traffic to Nessus port 8834. Follow the red colored boxes to setup the burp proxy.  

1.Screenshot for Burp Proxy Port Binding  
<kbd>![alt text](https://github.com/V9Y1nf0S3C/NessusPro-Report-Exporter-Tool/blob/main/Screenshots/Burp_proxy_for_troubleshooting%20(1).png?raw=true)</kbd>  

2.Screenshot for redirecting the powershell traffic to Nessus    
<kbd>![alt text](https://github.com/V9Y1nf0S3C/NessusPro-Report-Exporter-Tool/blob/main/Screenshots/Burp_proxy_for_troubleshooting%20(2).png?raw=true)</kbd>

**4.Running the script in proxy mode:**  
Give the input as "https://127.0.0.1:8080" in the "Nessus Scanner URL + Port" input. Screenshot provided below for your reference.
<kbd>![alt text](https://github.com/V9Y1nf0S3C/NessusPro-Report-Exporter-Tool/blob/main/Screenshots/Burp_proxy_for_troubleshooting%20(3).png?raw=true)</kbd>

## Comments  
  
- Ensure that the correct execution policy is set when executing the script.


## Sample Screenshots   

1. Powershell Console I/O:  
<kbd>![alt text](https://github.com/V9Y1nf0S3C/NessusPro-Report-Exporter-Tool/blob/main/Screenshots/Sample_output.png?raw=true)</kbd>

2. Exported files using this script:  
<kbd>![alt text](https://github.com/V9Y1nf0S3C/NessusPro-Report-Exporter-Tool/blob/main/Screenshots/Exported_files.png?raw=true)</kbd>

