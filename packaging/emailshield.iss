; Inno Setup 6 script. Compile with:  ISCC.exe /DAppVersion=2.2.0 packaging\emailshield.iss   (build_windows.bat does this)
; UNTESTED: this script has never been compiled or run (no Windows/Inno Setup in the authoring environment).
#ifndef AppVersion
  #define AppVersion "2.3.0"
#endif
[Setup]
AppId={{B4C1E1D2-6A0F-4C61-9B53-0E5A0B7A2E11}
AppName=EmailShield
AppVersion={#AppVersion}
AppPublisher=EmailShield (unsigned build)
DefaultDirName={autopf}\EmailShield
DefaultGroupName=EmailShield
PrivilegesRequired=lowest
OutputDir=..\dist_installer
OutputBaseFilename=EmailShield-Setup-{#AppVersion}
SetupIconFile=emailshield.ico
UninstallDisplayIcon={app}\EmailShield.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
; the running engine holds this mutex: setup asks the user to close it instead of overwriting files in use
AppMutex=EmailShieldEngine
SetupLogging=yes
[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: checkedonce
[Files]
Source: "..\dist\EmailShield\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
[Icons]
Name: "{group}\EmailShield"; Filename: "{app}\EmailShield.exe"
Name: "{group}\Stop EmailShield engine"; Filename: "{app}\EmailShield.exe"; Parameters: "--stop"
Name: "{group}\Uninstall EmailShield"; Filename: "{uninstallexe}"
Name: "{autodesktop}\EmailShield"; Filename: "{app}\EmailShield.exe"; Tasks: desktopicon
[Run]
Filename: "{app}\EmailShield.exe"; Description: "Launch EmailShield"; Flags: nowait postinstall skipifsilent
[UninstallRun]
Filename: "{app}\EmailShield.exe"; Parameters: "--stop"; Flags: runhidden skipifdoesntexist; RunOnceId: "StopEngine"
Filename: "{app}\EmailShield.exe"; Parameters: "--autostart off"; Flags: runhidden skipifdoesntexist; RunOnceId: "RemoveAutostart"
[Code]
var
  DeleteData: Boolean;

// Upgrade safety: stop a running engine BEFORE files are replaced. User data (%APPDATA%\EmailShield) is never touched by install/upgrade.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Rc: Integer;
begin
  if FileExists(ExpandConstant('{app}\EmailShield.exe')) then
    Exec(ExpandConstant('{app}\EmailShield.exe'), '--stop', '', SW_HIDE, ewWaitUntilTerminated, Rc);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Rc: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    DeleteData := False;
    // Silent uninstalls ALWAYS keep the data. Interactive default answer is No.
    if not UninstallSilent then
      if MsgBox('Also delete your EmailShield data (scan history, settings, backups, stored credentials) in ' + ExpandConstant('{userappdata}\EmailShield') + '?' + #13#10 + #13#10 +
                'Choose No to keep it for a future installation. Choosing Yes also revokes Gmail access and removes stored credentials.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DeleteData := True;
        Exec(ExpandConstant('{app}\EmailShield.exe'), '--forget-credentials', '', SW_HIDE, ewWaitUntilTerminated, Rc);
      end;
  end;
  if (CurUninstallStep = usPostUninstall) and DeleteData then
    DelTree(ExpandConstant('{userappdata}\EmailShield'), True, True, True);
end;
