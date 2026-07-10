; MITM Proxy - Inno Setup installer script
; Bundles the pre-built app (Python venv, frontend, backend, Playwright browsers)
; into a single Windows installer EXE.
;
; Build with:  iscc setup.iss /DBuildDir=C:\path\to\_build

#ifndef BuildDir
  #define BuildDir "..\\_build"
#endif

[Setup]
AppName=MITM Proxy
AppVersion=1.0.0
AppPublisher=MITM Proxy
DefaultDirName={localappdata}\MitmProxy
DefaultGroupName=MITM Proxy
UninstallDisplayName=MITM Proxy
OutputDir={#BuildDir}\Output
OutputBaseFilename=MitmProxySetup
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
Source: "{#BuildDir}\MitmProxy.bat"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{localappdata}\MitmProxy\data"
Name: "{localappdata}\MitmProxy\screenshots"
Name: "{localappdata}\MitmProxy\certs"

[Icons]
Name: "{group}\MITM Proxy"; Filename: "{app}\MitmProxy.bat"; WorkingDir: "{app}"
Name: "{group}\Uninstall MITM Proxy"; Filename: "{uninstallexe}"
Name: "{autodesktop}\MITM Proxy"; Filename: "{app}\MitmProxy.bat"; WorkingDir: "{app}"

[Run]
Filename: "{app}\MitmProxy.bat"; Description: "Launch MITM Proxy"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\MitmProxy\screenshots"

[Code]
// Show a summary page before install
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result :=
    'MITM Proxy will be installed to:' + NewLine +
    Space + ExpandConstant('{app}') + NewLine + NewLine +
    'Data will be stored in:' + NewLine +
    Space + ExpandConstant('{localappdata}\MitmProxy\data') + NewLine + NewLine +
    'After installation:' + NewLine +
    Space + 'Main app:        http://localhost:8091' + NewLine +
    Space + 'Debug dashboard: http://localhost:8092' + NewLine + NewLine +
    'Custom CA certificates (.crt/.pem files):' + NewLine +
    Space + 'Place in ' + ExpandConstant('{localappdata}\MitmProxy\certs\');
end;
