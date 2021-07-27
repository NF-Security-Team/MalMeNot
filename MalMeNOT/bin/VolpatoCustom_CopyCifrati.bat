@echo off
rem set /p Extension="Scrivi la parola comune a tutti i files cifrati: "
set Extension="LeChiffre"
set BACKUP_PATH="\\svrfile-01\Dati\Scambio\cyber attack\%COMPUTERNAME%"

mkdir %BACKUP_PATH%\DiscoC
mkdir %BACKUP_PATH%\DiscoD
mkdir %BACKUP_PATH%\DiscoE
mkdir %BACKUP_PATH%\DiscoF

robocopy C:\ %BACKUP_PATH%\DiscoC "*%Extension%*" /MOV /s /XJ /R:3 /W:3 /A-:SH 
robocopy D:\ %BACKUP_PATH%\DiscoD "*%Extension%*" /MOV /s /XJ /R:3 /W:3 /A-:SH 
robocopy E:\ %BACKUP_PATH%\DiscoE "*%Extension%*" /MOV /s /XJ /R:3 /W:3 /A-:SH 
robocopy F:\ %BACKUP_PATH%\DiscoF "*%Extension%*" /MOV /s /XJ /R:3 /W:3 /A-:SH 
