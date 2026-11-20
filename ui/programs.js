// "What is this program?" A plain-words note for common Windows programs, by file name.
// [friendly name, what it is, expected publisher (signer must contain one of the |-separated
//  words; '' = not checked), how much it normally uploads (2 = a lot is normal, 1 = small
//  amounts, 0 = hardly anything), part of Windows (must live in the Windows folder)]
'use strict';
const UPLOAD_NOTE = [
  'It should hardly send anything. Large uploads from it are unusual.',
  'It sends small amounts: updates, sign-in, usage data.',
  'Uploading is normal for it: it sends what you share, sync or post.',
];
const PROGRAMS = (() => {
  const P = {};
  const add = (win, pub, up, list) => list.forEach(([exe, n, w]) => (P[exe] = { n, w, p: pub, up, win }));
  const one = (exe, n, w, pub, up, win = false) => (P[exe] = { n, w, p: pub, up, win });

  // ---- Windows itself: these always live in C:\Windows
  add(true, 'Microsoft', 0, [
    ['lsass.exe', 'Windows sign-in security', 'Checks your Windows password and signs you in to work or school accounts. A core part of Windows.'],
    ['services.exe', 'Windows service manager', 'Starts and stops Windows background services. A core part of Windows.'],
    ['wininit.exe', 'Windows start-up', 'Starts Windows when the PC boots. A core part of Windows.'],
    ['winlogon.exe', 'Windows sign-in screen', 'Handles signing in, locking and signing out. A core part of Windows.'],
    ['csrss.exe', 'Windows client/server runtime', 'Manages windows and consoles. A core part of Windows.'],
    ['smss.exe', 'Windows session manager', 'Starts your Windows session. A core part of Windows.'],
    ['dwm.exe', 'Desktop Window Manager', 'Draws the windows on your screen.'],
    ['conhost.exe', 'Console window host', 'The window behind Command Prompt and PowerShell.'],
    ['ctfmon.exe', 'Keyboard and language input', 'Handles typing, keyboard layouts and the language bar.'],
    ['sihost.exe', 'Shell infrastructure host', 'Runs parts of the desktop such as the Action Center.'],
    ['fontdrvhost.exe', 'Font driver host', 'Draws fonts.'],
    ['dllhost.exe', 'COM Surrogate', 'Runs small Windows helpers, for example making picture thumbnails.'],
    ['audiodg.exe', 'Windows audio', 'Processes sound for the speakers and microphone.'],
    ['searchindexer.exe', 'Windows Search indexer', 'Builds the index that makes searching your files fast. Works only on this PC.'],
    ['searchprotocolhost.exe', 'Windows Search helper', 'Reads files for the search index. Works only on this PC.'],
    ['searchfilterhost.exe', 'Windows Search helper', 'Reads files for the search index. Works only on this PC.'],
    ['tiworker.exe', 'Windows Modules Installer', 'Installs Windows updates that were already downloaded.'],
    ['trustedinstaller.exe', 'Windows Modules Installer', 'Installs and removes Windows updates and features.'],
    ['textinputhost.exe', 'Touch keyboard and emoji panel', 'Shows the on-screen keyboard and the emoji picker (Win + .).'],
    ['wudfhost.exe', 'Windows driver host', 'Runs drivers for devices such as fingerprint readers and USB devices.'],
    ['sgrmbroker.exe', 'System Guard', 'Checks that Windows started up untouched.'],
    ['lsaiso.exe', 'Credential Guard', 'Keeps Windows passwords in a protected area.'],
    ['securityhealthsystray.exe', 'Windows Security tray icon', 'The shield icon near the clock.'],
    ['taskmgr.exe', 'Task Manager', 'Shows running programs. Opened by you with Ctrl+Shift+Esc.'],
    ['mmc.exe', 'Management Console', 'Opens Windows admin tools (services, certificates, event viewer).'],
    ['cmd.exe', 'Command Prompt', 'Runs typed commands and .bat scripts. Malware uses it to run other tools, so going online by itself is worth a look.'],
    ['powershell.exe', 'Windows PowerShell', 'Runs commands and scripts. Malware uses it a lot to download more malware and send data out; going online is worth a look unless you or your IT ran a script.'],
    ['powershell_ise.exe', 'PowerShell ISE', 'An editor for PowerShell scripts.'],
    ['wscript.exe', 'Windows Script Host', 'Runs .vbs and .js script files. Rarely needed today and very often used by malware attached to emails.'],
    ['cscript.exe', 'Windows Script Host (console)', 'Runs .vbs and .js script files. Rarely needed today and very often used by malware.'],
    ['mshta.exe', 'HTML Application host', 'Runs .hta files. Almost only malware uses it today.'],
    ['certutil.exe', 'Certificate tool', 'Manages certificates. Malware abuses it to download files, so it going online is suspicious.'],
    ['bitsadmin.exe', 'Background transfer tool', 'Old tool for background downloads. Malware abuses it to download files.'],
    ['rundll32.exe', 'Run a DLL', 'Starts code inside DLL files for Windows. Malware hides behind it too; going online is worth a look.'],
    ['regsvr32.exe', 'Register a DLL', 'Registers program parts. Malware abuses it to run code from the internet.'],
    ['wmic.exe', 'WMI command line', 'Reads and changes system settings. Malware uses it for spying on the PC.'],
    ['schtasks.exe', 'Task Scheduler command', 'Creates scheduled tasks. Malware uses it to start itself again.'],
    ['nslookup.exe', 'Name lookup tool', 'Looks up internet names. Used by people troubleshooting, and by some malware.'],
    ['ping.exe', 'Ping', 'Checks whether another computer answers.'],
    ['tracert.exe', 'Trace route', 'Shows the path to another computer.'],
  ]);
  // Same names also ship outside C:\Windows (Store versions, Visual Studio, Git), so no folder check.
  add(false, 'Microsoft', 0, [
    ['notepad.exe', 'Notepad', 'Simple text editor.'],
    ['mspaint.exe', 'Paint', 'Simple drawing program.'],
    ['msbuild.exe', 'MSBuild', 'Builds .NET programs. Malware abuses it to run hidden code.'],
  ]);
  add(false, 'Microsoft', 1, [
    ['wsl.exe', 'Windows Subsystem for Linux', 'Runs Linux inside Windows; its network traffic shows here.'],
    ['wslhost.exe', 'Windows Subsystem for Linux', 'Helper for Linux inside Windows.'],
    ['wslservice.exe', 'Windows Subsystem for Linux', 'Service for Linux inside Windows.'],
  ]);
  one('curl.exe', 'curl download tool', 'Downloads and uploads files from the command line. Fine when you or a script you trust ran it.', '', 0);
  one('ssh.exe', 'SSH client', 'Connects to other computers over SSH. Used by developers and administrators.', '', 1);
  add(true, 'Microsoft', 1, [
    ['svchost.exe', 'Windows service host', 'Runs Windows background services: updates, time sync, network, printing. Which ones is listed under it.'],
    ['explorer.exe', 'File Explorer and taskbar', 'Your desktop, taskbar and file windows.'],
    ['searchhost.exe', 'Windows Search box', 'The search on the taskbar. Sends what you type to Bing for web results unless that is turned off.'],
    ['searchapp.exe', 'Windows Search box', 'The search on the taskbar. Sends what you type to Bing for web results unless that is turned off.'],
    ['startmenuexperiencehost.exe', 'Start menu', 'The Start menu, including its suggestions.'],
    ['shellexperiencehost.exe', 'Windows shell', 'Clock, calendar and notification panels.'],
    ['runtimebroker.exe', 'Runtime Broker', 'Checks what Store apps are allowed to do.'],
    ['backgroundtaskhost.exe', 'Background tasks', 'Runs background work for Store apps (live tiles, sync).'],
    ['taskhostw.exe', 'Task host', 'Runs scheduled Windows tasks.'],
    ['spoolsv.exe', 'Print Spooler', 'Sends documents to printers, including network printers.'],
    ['wuauclt.exe', 'Windows Update', 'Checks for and downloads Windows updates.'],
    ['usoclient.exe', 'Windows Update', 'Starts Windows Update scans.'],
    ['mousocoreworker.exe', 'Windows Update', 'Downloads and prepares Windows updates.'],
    ['musnotification.exe', 'Windows Update notices', 'Shows update and restart reminders.'],
    ['securityhealthservice.exe', 'Windows Security', 'Keeps track of antivirus, firewall and device security.'],
    ['smartscreen.exe', 'SmartScreen', 'Asks Microsoft whether a downloaded file or website is known to be dangerous.'],
    ['wermgr.exe', 'Windows Error Reporting', 'Sends crash reports to Microsoft.'],
    ['werfault.exe', 'Windows Error Reporting', 'Collects and sends a crash report after a program crashed.'],
    ['compattelrunner.exe', 'Microsoft Compatibility Telemetry', 'Sends usage and compatibility data to Microsoft. Can be turned off on the Blocking tab (Analytics).'],
    ['devicecensus.exe', 'Device Census', 'Sends a description of this PC\'s hardware to Microsoft (telemetry).'],
    ['sppsvc.exe', 'Windows activation', 'Checks the Windows licence with Microsoft.'],
    ['slui.exe', 'Windows activation', 'Activates the Windows licence.'],
    ['lockapp.exe', 'Lock screen', 'The lock screen, including Windows Spotlight pictures.'],
    ['systemsettings.exe', 'Settings', 'The Windows Settings app.'],
    ['dashost.exe', 'Device association', 'Pairs Bluetooth, network and wireless devices.'],
    ['msiexec.exe', 'Windows Installer', 'Installs and removes programs (.msi files).'],
    ['rdpclip.exe', 'Remote Desktop clipboard', 'Copies and pastes between this PC and a Remote Desktop session.'],
  ]);
  add(true, 'Microsoft', 2, [
    ['mstsc.exe', 'Remote Desktop Connection', 'You use it to control another computer. Sends your keyboard and mouse there.'],
    ['msra.exe', 'Windows Remote Assistance', 'Lets someone else see and control this screen. Only use it with people you know; scam "support" callers ask for this.'],
  ]);
  P['system'] = { n: 'Windows kernel', w: 'The core of Windows. Handles file sharing, network discovery and some built-in web services.', p: '', up: 1, win: false };

  // ---- Microsoft programs that live outside C:\Windows
  add(false, 'Microsoft', 1, [
    ['msmpeng.exe', 'Microsoft Defender Antivirus', 'The antivirus built into Windows. Sends reports and, if allowed, suspicious files to Microsoft.'],
    ['mpdefendercoreservice.exe', 'Microsoft Defender', 'Part of the antivirus built into Windows.'],
    ['nissrv.exe', 'Microsoft Defender network inspection', 'Checks network traffic for known attacks.'],
    ['mpcmdrun.exe', 'Microsoft Defender tool', 'Updates virus definitions and runs scans.'],
    ['widgets.exe', 'Widgets', 'The news and weather board on the taskbar.'],
    ['microsoftedgeupdate.exe', 'Microsoft Edge Update', 'Keeps Edge and WebView2 up to date.'],
    ['onedrivestandaloneupdater.exe', 'OneDrive Update', 'Keeps OneDrive up to date.'],
    ['officeclicktorun.exe', 'Microsoft Office Click-to-Run', 'Installs and updates Microsoft Office.'],
    ['officec2rclient.exe', 'Microsoft Office updates', 'Installs Office updates.'],
    ['msoia.exe', 'Office telemetry', 'Sends Office usage data to Microsoft.'],
    ['gamebar.exe', 'Xbox Game Bar', 'Screen recording and game overlay (Win + G).'],
    ['gamebarftserver.exe', 'Xbox Game Bar', 'Helper for the game overlay.'],
    ['gamingservices.exe', 'Xbox Gaming Services', 'Installs and runs games from the Xbox app and Game Pass.'],
    ['xboxpcapp.exe', 'Xbox app', 'The Xbox app for PC games.'],
    ['winstore.app.exe', 'Microsoft Store', 'Installs and updates apps from the Store.'],
    ['microsoft.photos.exe', 'Photos', 'The Photos app; can sync with OneDrive.'],
    ['msaccess.exe', 'Microsoft Access', 'Database program from Office.'],
    ['mspub.exe', 'Microsoft Publisher', 'Desktop publishing from Office.'],
    ['code.exe', 'Visual Studio Code', 'A code editor. Extensions and settings sync go online.'],
    ['devenv.exe', 'Visual Studio', 'Microsoft\'s programming tool.'],
    ['quickassist.exe', 'Quick Assist', 'Lets someone else see and control this screen. Scam "support" callers ask for exactly this; only use it with people you know.'],
  ]);
  add(false, 'Microsoft', 2, [
    ['msedge.exe', 'Microsoft Edge', 'Web browser made by Microsoft. Uploads are normal when you send mail, post or upload on a site.'],
    ['msedgewebview2.exe', 'Edge WebView2', 'Shows web pages inside other apps (Teams, Outlook, Widgets). Its traffic belongs to the app that started it.'],
    ['onedrive.exe', 'OneDrive', 'Microsoft\'s cloud storage. Uploads every file you save in your OneDrive folders, Desktop or Documents if backup is on.'],
    ['filecoauth.exe', 'Office co-authoring', 'Syncs Office files you edit together with others in OneDrive or SharePoint.'],
    ['phoneexperiencehost.exe', 'Phone Link', 'Connects your phone: messages, photos and calls.'],
    ['yourphone.exe', 'Phone Link', 'Connects your phone: messages, photos and calls.'],
    ['hxoutlook.exe', 'Mail and Calendar', 'The old Windows Mail app.'],
    ['hxtsr.exe', 'Mail and Calendar sync', 'Syncs the old Windows Mail app.'],
    ['olk.exe', 'Outlook (new)', 'Email and calendar.'],
    ['outlook.exe', 'Outlook', 'Email and calendar. Sending mail with attachments is an upload.'],
    ['winword.exe', 'Microsoft Word', 'Word processor. Saves to OneDrive or SharePoint when you use them.'],
    ['excel.exe', 'Microsoft Excel', 'Spreadsheets. Saves to OneDrive or SharePoint when you use them.'],
    ['powerpnt.exe', 'Microsoft PowerPoint', 'Presentations. Saves to OneDrive or SharePoint when you use them.'],
    ['onenote.exe', 'OneNote', 'Notes, synced to OneDrive.'],
    ['ms-teams.exe', 'Microsoft Teams', 'Chat, calls and meetings. Video calls and screen sharing upload a lot.'],
    ['teams.exe', 'Microsoft Teams', 'Chat, calls and meetings. Video calls and screen sharing upload a lot.'],
    ['lync.exe', 'Skype for Business', 'Chat, calls and meetings.'],
  ]);
  one('skype.exe', 'Skype', 'Calls and chat. Calls upload a lot.', 'Skype|Microsoft', 2);

  // ---- browsers
  one('chrome.exe', 'Google Chrome', 'Web browser. Uploads are normal when you send mail, post or upload on a site.', 'Google', 2);
  one('firefox.exe', 'Mozilla Firefox', 'Web browser. Uploads are normal when you send mail, post or upload on a site.', 'Mozilla', 2);
  one('brave.exe', 'Brave', 'Web browser. Uploads are normal when you send mail, post or upload on a site.', 'Brave', 2);
  one('opera.exe', 'Opera', 'Web browser. Uploads are normal when you send mail, post or upload on a site.', 'Opera', 2);
  one('vivaldi.exe', 'Vivaldi', 'Web browser. Uploads are normal when you send mail, post or upload on a site.', 'Vivaldi', 2);
  one('iexplore.exe', 'Internet Explorer', 'The old Microsoft browser.', 'Microsoft', 2);
  one('googleupdate.exe', 'Google Update', 'Keeps Chrome and other Google programs up to date.', 'Google', 1);
  one('maintenanceservice.exe', 'Firefox update service', 'Installs Firefox updates.', 'Mozilla', 1);
  one('braveupdate.exe', 'Brave Update', 'Keeps Brave up to date.', 'Brave', 1);

  // ---- chat and calls
  const chat = 'Chat and calls. Sending files, photos and video calls upload a lot.';
  one('discord.exe', 'Discord', chat + ' Malware also uses Discord to send stolen data, so check uploads you did not make.', 'Discord', 2);
  one('telegram.exe', 'Telegram', chat + ' Malware also uses Telegram bots to send stolen data.', 'Telegram', 2);
  one('whatsapp.exe', 'WhatsApp', chat, 'WhatsApp|Meta', 2);
  one('signal.exe', 'Signal', chat, 'Signal', 2);
  one('slack.exe', 'Slack', chat, 'Slack', 2);
  one('zoom.exe', 'Zoom', 'Video meetings. Calls and screen sharing upload a lot.', 'Zoom', 2);
  one('cpthost.exe', 'Zoom screen sharing', 'Shares your screen in a Zoom meeting.', 'Zoom', 2);
  one('ciscocollabhost.exe', 'Webex', 'Video meetings. Calls and screen sharing upload a lot.', 'Cisco', 2);
  one('webex.exe', 'Webex', 'Video meetings. Calls and screen sharing upload a lot.', 'Cisco', 2);
  one('viber.exe', 'Viber', chat, 'Viber', 2);
  one('line.exe', 'LINE', chat, 'LINE|LY Corp', 2);
  one('wechat.exe', 'WeChat', chat, 'Tencent', 2);
  one('weixin.exe', 'WeChat', chat, 'Tencent', 2);
  one('messenger.exe', 'Messenger', chat, '', 2);

  // ---- cloud storage
  const cloud = 'Cloud storage: uploads the files in its folder so they are backed up and on your other devices.';
  one('dropbox.exe', 'Dropbox', cloud, 'Dropbox', 2);
  one('googledrivefs.exe', 'Google Drive', cloud, 'Google', 2);
  one('iclouddrive.exe', 'iCloud Drive', cloud, 'Apple', 2);
  one('icloudservices.exe', 'iCloud', 'Syncs photos, passwords and files with Apple\'s iCloud.', 'Apple', 2);
  one('megasync.exe', 'MEGA', cloud, 'Mega', 2);
  one('nextcloud.exe', 'Nextcloud', cloud, 'Nextcloud', 2);
  one('owncloud.exe', 'ownCloud', cloud, 'ownCloud', 2);

  // ---- graphics and device makers
  one('nvcontainer.exe', 'NVIDIA Container', 'Runs NVIDIA graphics tools (GeForce Experience, driver updates). Sends some usage data to NVIDIA.', 'NVIDIA', 1);
  one('nvdisplay.container.exe', 'NVIDIA display driver', 'Part of the NVIDIA graphics driver.', 'NVIDIA', 1);
  one('nvidia share.exe', 'NVIDIA overlay', 'Game recording and overlay (ShadowPlay).', 'NVIDIA', 1);
  one('nvidia web helper.exe', 'NVIDIA web helper', 'Signs in to NVIDIA and checks for drivers.', 'NVIDIA', 1);
  one('nvidia app.exe', 'NVIDIA app', 'Driver updates and game settings.', 'NVIDIA', 1);
  one('igfxem.exe', 'Intel graphics', 'Part of the Intel graphics driver.', 'Intel', 0);
  one('esrv.exe', 'Intel Driver & Support Assistant', 'Checks for Intel driver updates.', 'Intel', 1);
  one('dsaservice.exe', 'Intel Driver & Support Assistant', 'Checks for Intel driver updates.', 'Intel', 1);
  one('amdrsserv.exe', 'AMD Radeon Software', 'AMD graphics settings and driver updates.', 'Advanced Micro Devices|AMD', 1);
  one('radeonsoftware.exe', 'AMD Radeon Software', 'AMD graphics settings and driver updates.', 'Advanced Micro Devices|AMD', 1);
  one('rtkauduservice64.exe', 'Realtek audio', 'Part of the sound driver.', 'Realtek', 0);
  one('supportassistagent.exe', 'Dell SupportAssist', 'Dell\'s update and support tool. Sends hardware details to Dell.', 'Dell', 1);
  one('lenovovantageservice.exe', 'Lenovo Vantage', 'Lenovo\'s update and settings tool.', 'Lenovo', 1);
  one('hpcommrecovery.exe', 'HP support tool', 'HP\'s update and support tool.', 'HP', 1);

  // ---- media and games
  one('spotify.exe', 'Spotify', 'Music streaming. Mostly downloads.', 'Spotify', 1);
  one('vlc.exe', 'VLC media player', 'Plays videos and music. Only checks for updates.', 'VideoLAN', 0);
  one('itunes.exe', 'iTunes', 'Apple music and iPhone backup.', 'Apple', 1);
  one('obs64.exe', 'OBS Studio', 'Records and streams video. Live streaming uploads a lot.', '', 2);
  one('steam.exe', 'Steam', 'Game store and launcher. Mostly downloads games.', 'Valve', 1);
  one('steamwebhelper.exe', 'Steam', 'Shows the Steam store and community pages.', 'Valve', 1);
  one('epicgameslauncher.exe', 'Epic Games Launcher', 'Game store and launcher. Mostly downloads games.', 'Epic Games', 1);
  one('battle.net.exe', 'Battle.net', 'Blizzard game launcher.', 'Blizzard', 1);
  one('eadesktop.exe', 'EA app', 'Electronic Arts game launcher.', 'Electronic Arts', 1);
  one('upc.exe', 'Ubisoft Connect', 'Ubisoft game launcher.', 'Ubisoft', 1);
  one('riotclientservices.exe', 'Riot Client', 'Riot Games launcher (League of Legends, Valorant).', 'Riot Games', 1);
  one('galaxyclient.exe', 'GOG Galaxy', 'GOG game launcher.', 'GOG', 1);
  one('audacity.exe', 'Audacity', 'Sound recorder and editor.', '', 0);

  // ---- Adobe
  one('acrobat.exe', 'Adobe Acrobat', 'Opens and edits PDF files. Can save to Adobe\'s cloud.', 'Adobe', 1);
  one('acrord32.exe', 'Adobe Acrobat Reader', 'Opens PDF files.', 'Adobe', 1);
  one('photoshop.exe', 'Adobe Photoshop', 'Photo editor.', 'Adobe', 1);
  one('adobe desktop service.exe', 'Adobe Creative Cloud', 'Installs Adobe apps and syncs your Creative Cloud files.', 'Adobe', 2);
  one('creative cloud.exe', 'Adobe Creative Cloud', 'Installs Adobe apps and syncs your Creative Cloud files.', 'Adobe', 2);
  one('adobearm.exe', 'Adobe Updater', 'Keeps Adobe programs up to date.', 'Adobe', 1);
  one('adobecollabsync.exe', 'Adobe Acrobat sync', 'Syncs shared PDF reviews.', 'Adobe', 1);
  one('agsservice.exe', 'Adobe Genuine Service', 'Checks that Adobe software is licensed.', 'Adobe', 1);

  // ---- developer tools
  one('git.exe', 'Git', 'Version control for code. "git push" uploads code to a server such as GitHub.', '', 2);
  one('git-remote-https.exe', 'Git', 'Moves code to and from a server such as GitHub.', '', 2);
  one('node.exe', 'Node.js', 'Runs JavaScript programs. What it sends depends on the script it runs.', '', 1);
  one('python.exe', 'Python', 'Runs Python programs. What it sends depends on the script it runs.', '', 1);
  one('pythonw.exe', 'Python (no window)', 'Runs Python programs without a window. Malware written in Python uses this too.', '', 1);
  one('java.exe', 'Java', 'Runs Java programs (Minecraft, business tools).', '', 1);
  one('javaw.exe', 'Java (no window)', 'Runs Java programs without a window (Minecraft, business tools).', '', 1);
  one('com.docker.backend.exe', 'Docker Desktop', 'Runs containers for developers.', 'Docker', 1);
  one('putty.exe', 'PuTTY', 'Connects to other computers over SSH.', 'Simon Tatham', 1);
  one('winscp.exe', 'WinSCP', 'Copies files to and from servers. Uploads are normal.', 'Martin', 2);
  one('filezilla.exe', 'FileZilla', 'Copies files to and from servers. Uploads are normal.', 'Tim Kosse', 2);
  one('postman.exe', 'Postman', 'Tests web APIs for developers.', 'Postman', 1);
  one('idea64.exe', 'IntelliJ IDEA', 'Programming tool by JetBrains.', 'JetBrains', 1);
  one('pycharm64.exe', 'PyCharm', 'Programming tool by JetBrains.', 'JetBrains', 1);

  // ---- security and VPN
  one('mbamservice.exe', 'Malwarebytes', 'Antivirus. Checks files and sites with Malwarebytes.', 'Malwarebytes', 1);
  one('avastsvc.exe', 'Avast Antivirus', 'Antivirus. Checks files and sites with Avast.', 'Avast|Gen Digital', 1);
  one('avgsvc.exe', 'AVG Antivirus', 'Antivirus. Checks files and sites with AVG.', 'AVG|Avast|Gen Digital', 1);
  one('bdservicehost.exe', 'Bitdefender', 'Antivirus. Checks files and sites with Bitdefender.', 'Bitdefender', 1);
  one('ekrn.exe', 'ESET', 'Antivirus. Checks files and sites with ESET.', 'ESET', 1);
  one('avp.exe', 'Kaspersky', 'Antivirus. Checks files and sites with Kaspersky.', 'Kaspersky', 1);
  one('mfemms.exe', 'McAfee', 'Antivirus. Checks files and sites with McAfee.', 'McAfee', 1);
  one('nortonsvc.exe', 'Norton', 'Antivirus. Checks files and sites with Norton.', 'Gen Digital|NortonLifeLock|Symantec', 1);
  const vpn = 'VPN: sends all your internet traffic through its own server, so the traffic of other programs is counted here too.';
  one('nordvpn.exe', 'NordVPN', vpn, 'nordvpn', 2);
  one('expressvpn.exe', 'ExpressVPN', vpn, 'Express', 2);
  one('protonvpn.exe', 'Proton VPN', vpn, 'Proton', 2);
  one('openvpn.exe', 'OpenVPN', vpn, 'OpenVPN', 2);
  one('openvpn-gui.exe', 'OpenVPN', vpn, 'OpenVPN', 1);
  one('wireguard.exe', 'WireGuard', vpn, 'WireGuard', 2);
  one('tailscaled.exe', 'Tailscale', 'Private network between your own devices. Traffic to your other devices goes through it.', 'Tailscale', 2);
  one('tailscale-ipn.exe', 'Tailscale', 'Private network between your own devices.', 'Tailscale', 1);
  one('vpnui.exe', 'Cisco Secure Client', 'Company VPN.', 'Cisco', 1);
  one('vpnagent.exe', 'Cisco Secure Client', vpn, 'Cisco', 2);
  one('forticlient.exe', 'FortiClient', 'Company VPN and security.', 'Fortinet', 1);
  one('pangpa.exe', 'GlobalProtect', 'Company VPN.', 'Palo Alto', 1);

  // ---- remote control: fine with your own IT, the classic tool of support scams
  const rc = 'Remote control: someone on another computer can see and control this screen. Fine with your own IT; scammers who call about "problems with your PC" install exactly these tools.';
  one('anydesk.exe', 'AnyDesk', rc, 'AnyDesk|philandro', 2);
  one('teamviewer.exe', 'TeamViewer', rc, 'TeamViewer', 2);
  one('teamviewer_service.exe', 'TeamViewer service', rc, 'TeamViewer', 2);
  one('rustdesk.exe', 'RustDesk', rc, 'Purslane', 2);
  one('ultraviewer_desktop.exe', 'UltraViewer', rc, '', 2);
  one('screenconnect.windowsclient.exe', 'ScreenConnect', rc, 'ConnectWise', 2);
  one('screenconnect.clientservice.exe', 'ScreenConnect', rc, 'ConnectWise', 2);
  one('srstreamer.exe', 'Splashtop', rc, 'Splashtop', 2);
  one('remoting_host.exe', 'Chrome Remote Desktop', rc, 'Google', 2);
  one('parsecd.exe', 'Parsec', rc, 'Parsec', 2);
  one('lmiguardiansvc.exe', 'LogMeIn', rc, 'LogMeIn|GoTo', 2);
  one('supremo.exe', 'Supremo', rc, 'Nanosystems', 2);
  one('aa_v3.exe', 'Ammyy Admin', rc, '', 2);
  one('tvnserver.exe', 'TightVNC', rc, '', 2);
  one('winvnc.exe', 'UltraVNC', rc, '', 2);
  one('vncserver.exe', 'RealVNC', rc, 'RealVNC', 2);

  // ---- password managers
  one('1password.exe', '1Password', 'Password manager. Syncs your encrypted vault.', 'AgileBits', 1);
  one('bitwarden.exe', 'Bitwarden', 'Password manager. Syncs your encrypted vault.', 'Bitwarden', 1);
  one('keepass.exe', 'KeePass', 'Password manager that keeps passwords in a file on this PC.', 'Dominik Reichl', 0);
  one('keepassxc.exe', 'KeePassXC', 'Password manager that keeps passwords in a file on this PC.', '', 0);

  // ---- file sharing, screenshots, notes, tools
  const p2p = 'File sharing (torrents): while it runs it uploads pieces of what you downloaded to other people. Big uploads are normal.';
  one('qbittorrent.exe', 'qBittorrent', p2p, '', 2);
  one('utorrent.exe', 'uTorrent', p2p, 'BitTorrent|Rainberry', 2);
  one('bittorrent.exe', 'BitTorrent', p2p, 'BitTorrent|Rainberry', 2);
  one('sharex.exe', 'ShareX', 'Screenshot tool that can upload screenshots to the internet.', '', 2);
  one('lightshot.exe', 'Lightshot', 'Screenshot tool that uploads screenshots to prnt.sc when you share them (public links).', '', 2);
  one('gyazo.exe', 'Gyazo', 'Screenshot tool that uploads screenshots to gyazo.com.', 'Nota', 2);
  one('greenshot.exe', 'Greenshot', 'Screenshot tool.', '', 0);
  one('notion.exe', 'Notion', 'Notes and documents, stored online.', 'Notion', 2);
  one('evernote.exe', 'Evernote', 'Notes, stored online.', 'Evernote', 2);
  one('obsidian.exe', 'Obsidian', 'Notes on this PC; syncs only if you pay for Sync.', 'Dynalist|Obsidian', 1);
  one('figma.exe', 'Figma', 'Design tool, works online.', 'Figma', 2);
  one('figma_agent.exe', 'Figma font helper', 'Lets figma.com use fonts installed on this PC.', 'Figma', 0);
  one('canva.exe', 'Canva', 'Design tool, works online.', 'Canva', 2);
  one('chatgpt.exe', 'ChatGPT', 'AI chat by OpenAI. What you type or attach is sent to OpenAI.', 'OpenAI', 2);
  one('claude.exe', 'Claude', 'AI chat by Anthropic. What you type or attach is sent to Anthropic.', 'Anthropic', 2);
  one('winrar.exe', 'WinRAR', 'Opens and makes .zip and .rar archives.', 'win.rar', 0);
  one('7zfm.exe', '7-Zip', 'Opens and makes archives.', '', 0);
  one('7zg.exe', '7-Zip', 'Opens and makes archives.', '', 0);
  one('everything.exe', 'Everything', 'Fast file search on this PC.', 'voidtools', 0);
  one('notepad++.exe', 'Notepad++', 'Text and code editor. Only checks for updates.', '', 1);
  return P;
})();

const KIND_SITES = /(^|\.)(discord(app)?\.(com|net)|cdn\.discordapp\.com|t\.me|telegram\.org|githubusercontent\.com|mediafire\.com|mega\.(nz|io)|dropboxusercontent\.com|gofile\.io|transfer\.sh|pastebin\.com|4shared\.com|sendspace\.com|anonfiles\.com|bit\.ly|tinyurl\.com|qu\.ax|catbox\.moe|filebin\.net)$/i;
const ODD_TLD = /\.(top|xyz|zip|click|icu|cfd|sbs|rest|shop|live|monster|lol|quest|cam|buzz|gq|tk|ml|cf|ga)$/i;

// Library entry for a program row (null when it is not a common program).
function progInfo(p) {
  if (!p) return null;
  const n = String(p.name || (p.exe || '').split('\\').pop() || '').toLowerCase();
  return PROGRAMS[n] || null;
}

// Why a program only looks like the program its name says ('' when nothing is off).
function lookalike(p) {
  const L = progInfo(p);
  if (!L || !p.exe || p.own) return '';
  const lower = p.exe.toLowerCase();
  if (L.win && p.class && p.class !== 'system' && p.class !== 'unknown') return `Named like Windows' own ${p.name}, but it is not in the Windows folder. Malware copies Windows names to blend in.`;
  if (lower.includes('\\windowsapps\\') || !L.p) return '';
  const re = new RegExp(L.p.split('|').map(w => w.replace(/[.*+?^${}()[\]\\]/g, '\\$&')).join('|'), 'i');
  if (p.sig === 'signed' && p.signer && !re.test(p.signer)) return `Named like ${L.n}, but signed by ${p.signer}, not ${L.p.split('|')[0]}.`;
  if (p.sig === 'unsigned') return `Named like ${L.n}, but not signed. The real one is signed by ${L.p.split('|')[0]}.`;
  if (p.sig === 'invalid') return `Named like ${L.n}, but its signature is broken: the file was changed.`;
  return '';
}

// A downloaded program's source site is worth a second look.
function oddSource(site) {
  if (!site) return '';
  if (/^[\d.]+$|:/.test(site)) return 'It was downloaded straight from an IP address, not a named site.';
  if (KIND_SITES.test(site)) return 'Files shared through chat apps, file hosts and code sites are a common way malware spreads.';
  if (ODD_TLD.test(site)) return 'Cheap web addresses like this one are often used for malware downloads.';
  return '';
}
