@echo off
set remitent_file= remitent.cer
set destinatary_file= destinatary.cer
set keystore_file= keystore.jks
cls
echo Create CER files.
echo Create JKS file.
echo.
echo      remitent_file     =%remitent_file%
echo      destinatary_file  =%destinatary_file%
echo      keystore_file      =%keystore_file%
echo.
pause
echo.
"%JAVA_HOME%\bin\keytool.exe" -v -genkey -alias remitent_key -keyalg RSA -keysize 1024 -validity 365 -keypass remitentpassword -keystore %keystore_file% -storepass mystorepassword
"%JAVA_HOME%\bin\keytool.exe" -v -genkey -alias destinatary_key -keyalg RSA -keysize 1024 -validity 365 -keypass destinatarypassword -keystore %keystore_file% -storepass mystorepassword
"%JAVA_HOME%\bin\keytool.exe" -v -export -alias remitent_key -file %remitent_file% -keystore %keystore_file% -storepass mystorepassword
"%JAVA_HOME%\bin\keytool.exe" -v -export -alias destinatary_key -file %destinatary_file% -keystore %keystore_file% -storepass mystorepassword
