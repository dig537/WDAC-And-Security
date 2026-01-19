Initialize--WDACPolicy
echo "######################################################"
Prepare--DriverNamesForWDACPolicy -PathesToDriversWithNamesToDeny @("C:\Windows\System32\drivers\BTHUSB.SYS")
Prepare--NamesForWDACPolicy -DenyNames @("Everything-1.4.1.1030.x64-Setup.exe") -Audit $false
Prepare--DevsForWDACPolicy -DenyDevelopers @("Sophos Ltd") -SampleFile "E:\Загрузки\HitmanPro_x64.exe" -Audit $false