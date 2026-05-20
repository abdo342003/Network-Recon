; Inno Setup script template. Requires Inno Setup Compiler (ISCC.exe).
; Edit the paths and app name/icon as needed.

#define MyAppName "Network Recon"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "Abdellah ERRAOUI"

[Setup]
AppId={{0D0133A2-39D6-4F3C-8E7E-3D59A3D74A77}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\NetworkRecon
DefaultGroupName=Network Recon
OutputBaseFilename=NetworkRecon_{#MyAppVersion}_Installer
Compression=lzma
SolidCompression=yes
SetupIconFile=assets\app.ico
WizardStyle=modern
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\app.ico
UninstallDisplayName={#MyAppName}
UsePreviousAppDir=yes
UsePreviousTasks=yes
UsePreviousLanguage=yes
CloseApplications=yes
CloseApplicationsFilter=network_recon.exe
RestartApplications=no
RestartIfNeededByRun=no

[Files]
Source: "dist\network_recon.exe"; DestDir: "{app}"; Flags: ignoreversion restartreplace
Source: "assets\app.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Network Recon"; Filename: "{app}\network_recon.exe"; IconFilename: "{app}\app.ico"
Name: "{group}\Uninstall Network Recon"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Network Recon"; Filename: "{app}\network_recon.exe"; IconFilename: "{app}\app.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\network_recon.exe"; Description: "Launch Network Recon"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Cleanup optional per-user app data folder if it exists.
Type: filesandordirs; Name: "{localappdata}\NetworkRecon"

[Code]
procedure TryCloseRunningApp();
var
	ResultCode: Integer;
begin
	Exec(
		ExpandConstant('{cmd}'),
		'/C taskkill /F /T /IM network_recon.exe >nul 2>&1',
		'',
		SW_HIDE,
		ewWaitUntilTerminated,
		ResultCode
	);
	Sleep(600);
end;

function InitializeSetup(): Boolean;
begin
	TryCloseRunningApp();
	Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
	TryCloseRunningApp();
	Result := '';
end;

function InitializeUninstall(): Boolean;
begin
	Result :=
		MsgBox(
			'Do you want to uninstall ' + ExpandConstant('{#MyAppName}') + '?',
			mbConfirmation,
			MB_YESNO
		) = IDYES;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
	if CurUninstallStep = usDone then
		MsgBox(ExpandConstant('{#MyAppName}') + ' was removed successfully.', mbInformation, MB_OK);
end;
