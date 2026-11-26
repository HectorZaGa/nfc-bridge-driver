# Íconos de NFC Bridge Driver

Coloca aquí los archivos `.ico` (recomendado multi-resolución 16x16, 32x32, 48x48, 256x256 RGBA):

- `app.ico`: Ícono del ejecutable y servicio **NFC Bridge Driver** en Windows.
- `setup.ico`: Ícono del instalador (`nfc-bridge-driver-*-setup.exe`).
- `uninstall.ico`: Ícono del desinstalador (`DisplayIcon` en Aplicaciones instaladas de Windows).

Puedes copiarlos o convertirlos automáticamente desde `E:\Github\NFC Bridge\iconos\driver-win` ejecutando `sync-icons.ps1`.
Si `app.ico` u otro `.ico` no existe todavía, `build.rs` incrusta automáticamente un respaldo procedural y `VERSIONINFO` (`FileDescription = "NFC Bridge Driver"`).
