VTSCAN

VTSCAN is a lightweight Windows application that allows you to scan any local file for malicious content using the VirusTotal database.

1. Installation

Download the latest vtscan.exe file from the Releases page of this repository. Move the executable to a permanent folder on your computer.

2. Integration
  
To add the scanner to your right-click menu, you must update the Windows registry. Create a registry file with the following code, ensuring you replace "C:\Path\To\vtscan.exe" with the actual location of your file.

Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT*\shell\Scan with VirusTotal]

[HKEY_CLASSES_ROOT*\shell\Scan with VirusTotal\command]
@=""C:\Path\To\vtscan.exe" "%1""

3. Usage

Right-click any file on your computer and select Scan with VirusTotal. The first time you run the tool, you will be prompted to enter your VirusTotal API key. The application will then save this key to a config.json file in the same directory and display the security scan results in a terminal window.
