; BITM Proxy - Inno Setup installer script
; Bundles the pre-built app (Python venv, frontend, backend, Playwright browsers)
; into a single Windows installer EXE.
;
; Build with:  iscc setup.iss /DBuildDir=C:\path\to\_build

#ifndef BuildDir
  #define BuildDir "..\\_build"
#endif

[Setup]
AppName=BITM Proxy
AppVersion=1.0.0
AppPublisher=BITM Proxy
DefaultDirName={localappdata}\BitmProxy
DefaultGroupName=BITM Proxy
UninstallDisplayName=BITM Proxy
OutputDir={#BuildDir}\Output
OutputBaseFilename=BitmProxySetup
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=lowest
DisableProgramGroupPage=yes
DisableDirPage=no
SetupLogging=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
; Application files (pre-built in _build\app)
Source: "{#BuildDir}\app\*"; DestDir: "{app}\app"; Flags: recursesubdirs createallsubdirs
; Launcher
Source: "{#BuildDir}\BitmProxy.bat"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{localappdata}\BitmProxy\data"
Name: "{localappdata}\BitmProxy\screenshots"
Name: "{localappdata}\BitmProxy\certs"

[Icons]
Name: "{group}\BITM Proxy"; Filename: "{app}\BitmProxy.bat"; WorkingDir: "{app}"
Name: "{group}\Uninstall BITM Proxy"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BITM Proxy"; Filename: "{app}\BitmProxy.bat"; WorkingDir: "{app}"

[Run]
Filename: "{app}\BitmProxy.bat"; Description: "Launch BITM Proxy"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\BitmProxy\screenshots"

[Code]
// Show a summary page before install
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result :=
    'BITM Proxy will be installed to:' + NewLine +
    Space + ExpandConstant('{app}') + NewLine + NewLine +
    'Data will be stored in:' + NewLine +
    Space + ExpandConstant('{localappdata}\BitmProxy\data') + NewLine + NewLine +
    'After installation:' + NewLine +
    Space + 'Main app:        http://localhost:8091' + NewLine +
    Space + 'Debug dashboard: http://localhost:8092' + NewLine + NewLine +
    'Custom CA certificates (.crt/.pem files):' + NewLine +
    Space + 'Place in ' + ExpandConstant('{localappdata}\BitmProxy\certs\');
end;
