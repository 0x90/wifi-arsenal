@if "%1" EQU "-clean" goto clean
@if "%1" EQU "-Debug" goto Debug
@if "%1" EQU "-Release" goto Release
@echo Error driver_build.bat commandline!
goto Usage 

:Debug
pushd .
call %DDKPATH%\bin\setenv.bat %DDKPATH% chk x64 WIN7 no_oacr
popd
if "%2" NEQ "-re" skipcleanDebug
rmdir /S /Q .\Debug
rmdir /S /Q .\obj
rmdir /S /Q .\objchk
del buildchk.log
:skipcleanDebug
build
copy /Y objchk_win7_amd64\amd64\atheeprom.sys ..\Debug\ath64.sys
goto exit 

:Release
pushd .
call %DDKPATH%\bin\setenv.bat %DDKPATH% fre x64 WIN7 no_oacr
popd
if "%2" NEQ "-re" skipcleanRelease
rmdir /S /Q .\Release
rmdir /S /Q .\obj
rmdir /S /Q .\objfre
del buildfre.log
:skipcleanRelease
build
copy /Y objfre_win7_amd64\amd64\atheeprom.sys ..\Release\ath64.sys
goto exit 

:clean
rmdir /S /Q .\Release
rmdir /S /Q .\Debug
rmdir /S /Q .\obj
rmdir /S /Q .\objchk
rmdir /S /Q .\objfre
del buildchk.log
del buildfre.log
goto exit 

:Usage
@echo Usage:
@echo mybuild.bat -Debug [-re]   - compile with checked build env (Debug) [rebuild all]
@echo mybuild.bat -Release [-re] - compile with free    build env (Release) [rebuild all]
@echo mybuild.bat -clean         - remove temp folders and files 
@exit /B 1 

:exit
