; Inno Setup script -> avai-setup.exe
; Build (after PyInstaller produces dist\avai):
;   iscc /DAppVersion=%VERSION% packaging\windows\avai.iss
; UNVERIFIED until run in CI on a Windows runner.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppName=avai
AppVersion={#AppVersion}
AppPublisher=iklobato
DefaultDirName={autopf}\avai
DefaultGroupName=avai
UninstallDisplayIcon={app}\avai.exe
OutputBaseFilename=avai-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
; The app self-elevates (PyInstaller uac_admin), so the installer only needs
; per-machine install rights here.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
; PyInstaller onedir output.
Source: "..\..\dist\avai\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\avai"; Filename: "{app}\avai.exe"
Name: "{commondesktop}\avai"; Filename: "{app}\avai.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\avai.exe"; Description: "Launch avai"; Flags: nowait postinstall skipifsilent
