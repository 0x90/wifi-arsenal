set DDKPATH=D:\WinDDK\7600.16385.1

pushd .

setlocal
call build_x64.bat %1 %2 
endlocal

setlocal
call build_x86.bat %1 %2
endlocal

popd
