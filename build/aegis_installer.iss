; ============================================================================
; Aegis ICS — Inno Setup Installer Script
; ============================================================================
; Creates a professional Windows installer from the PyInstaller --onedir output.
;
; Compile with: iscc build\aegis_installer.iss
;   (Requires Inno Setup 6.x: https://jrsoftware.org/isdl.php)
;
; Prerequisites:
;   - PyInstaller must have already built dist\AegisICS\
;   - Microsoft Edge WebView2 Runtime (bundled bootstrapper optional)
; ============================================================================

#define MyAppName "Aegis ICS"
#define MyAppVersion "3.0.0"
#define MyAppPublisher "Aegis ICS Research Project"
#define MyAppURL "https://github.com/anshulsc/aegis-ics"
#define MyAppExeName "AegisICS.exe"

; Path to the PyInstaller --onedir output (relative to this .iss file)
#define SourceDir "..\dist\AegisICS"

[Setup]
; Unique application identifier (generate a new GUID for your build)
AppId={{8A7C3E2F-1D4B-4F6A-9E8D-2C5A7B3F1E9D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}

; Uninstaller
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

; Output installer file
OutputDir=..\installer_output
OutputBaseFilename=Aegis_ICS_Setup_v{#MyAppVersion}

; Installer appearance
WizardStyle=modern
; SetupIconFile=assets\app.ico
; WizardImageFile=assets\wizard_banner.bmp
; WizardSmallImageFile=assets\wizard_small.bmp

; Compression — maximum
Compression=lzma2/ultra64
SolidCompression=yes

; Allow per-user install (no admin required) with override dialog
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; Minimum Windows version: Windows 10
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Include the entire PyInstaller output recursively
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Optional: Bundle WebView2 bootstrapper for older Windows 10 versions
; Uncomment the lines below and place MicrosoftEdgeWebview2Setup.exe in build\assets\
; Source: "assets\MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
; Start Menu shortcut
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "Launch Aegis ICS Dashboard"

; Desktop shortcut (optional — user can uncheck during install)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; Comment: "Launch Aegis ICS Dashboard"

; Start Menu uninstall shortcut
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
; "Launch Aegis ICS" checkbox after install completes
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(#MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
// Check if Microsoft Edge WebView2 Runtime is installed
function IsWebView2Installed: Boolean;
var
  Version: string;
begin
  // Check 64-bit registry
  Result := RegQueryStringValue(HKLM,
    'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
    'pv', Version);
  
  // Fallback: check 32-bit registry
  if not Result then
    Result := RegQueryStringValue(HKLM,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', Version);

  // Fallback: check per-user install
  if not Result then
    Result := RegQueryStringValue(HKCU,
      'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', Version);
end;

function InitializeSetup(): Boolean;
begin
  Result := True;

  if not IsWebView2Installed then
  begin
    if MsgBox('Aegis ICS requires Microsoft Edge WebView2 Runtime.'#13#10 +
              'It is usually pre-installed on Windows 10/11.'#13#10#13#10 +
              'Would you like to continue anyway? (You may need to install WebView2 manually)',
              mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
    end;
  end;
end;
