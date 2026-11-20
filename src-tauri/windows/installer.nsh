; Kestryl's look for the Tauri NSIS installer. Tauri's installer.nsi includes this file
; (bundle > windows > nsis > installerHooks) right after MUI2, before any page is declared,
; so the settings below apply to its pages. The images and icons are set in tauri.conf.json.

; Current Windows controls and font instead of the classic ones.
XPStyle on
SetFont "Segoe UI" 9

; The bird sits on the right of the page header, the page title on the left.
!define MUI_HEADERIMAGE_RIGHT

!define MUI_WELCOMEPAGE_TITLE "Welcome to Kestryl"
!define MUI_WELCOMEPAGE_TEXT "Kestryl shows every program on this PC that sends or receives data, warns you when one behaves like data theft, and blocks it in one click.$\r$\n$\r$\nIt is free and open source, runs entirely on this PC and installs no driver.$\r$\n$\r$\nClick Next to continue."

!define MUI_FINISHPAGE_TITLE "Kestryl is ready"
!define MUI_FINISHPAGE_TEXT "Kestryl runs in the notification area next to the clock.$\r$\n$\r$\nWithout administrator rights it works in a limited mode. Click $\"Restart as administrator$\" in Kestryl for full protection."

; Tauri's template sets the other version fields of Setup.exe; the company is missing there.
VIAddVersionKey "CompanyName" "Kestryl"
