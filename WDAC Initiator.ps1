Save--MyPC
Initialize--WDACPolicy

# Существующие параметры:

echo "######################################################"
Prepare--DevsForWDACPolicy -DenyDevelopers @("YANDEX LLC") -SampleFile "C:\WDAC\Samples\Yandex.exe"
Prepare--NamesForWDACPolicy -DenyNames @("mracsvc.exe", "mracdrv1.sys")
Prepare--DevsForWDACPolicy -DenyDevelopers @("VK Play LLC") -SampleFile "C:\WDAC\Samples\VKPlayLoader_4a36b8f180deb2daf6dfb24976b613dd.exe"

# Новые параметры (после развёртки переместить в существующие):

Disable--Audit
