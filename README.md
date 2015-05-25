# README #

Serwer RADIUS z protokołem EAP-MD5. Zawiera klienta symulującego NAS do testów.

### Wymagania

* VS2012 albo Microsoft SDK

### Instalacja

* Ustaw odpowiednie zmienne środowiskowe. Dla VS2012 można to zrobić na dwa sposoby:
    - Otwórz Developer Command Prompt albo
    - Otwórz cmd.exe i uruchom vcvarsall.bat ( z argumentem amd64 dla komputerów x64)
* W terminalu przejdź do głównego katalogu z Makefile
* Uruchom 
    nmake