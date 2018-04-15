@ECHO OFF 
del loadapppid.txt
del fprintf.txt /y
loadapp.exe /d:detectpoll.dll /p:detectpoll.dll %1

md %1
copy fprintf.txt %1
