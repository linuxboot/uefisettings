echo -off
# The second boot of the scenario shell-global-variables, after the first set PlatformLang
# and OsIndications; shell/global-variables-reboot.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi variable get PlatformLang
echo uefisettings-shell: step platform-lang %lasterror%
uefisettings.efi variable get OsIndications
echo uefisettings-shell: step os-indications %lasterror%
uefisettings.efi variable get BootNext
echo uefisettings-shell: step boot-next-absent %lasterror%
uefisettings.efi variable set BootNext Boot0000
echo uefisettings-shell: step boot-next %lasterror%
uefisettings.efi variable get BootNext
echo uefisettings-shell: step boot-next-get %lasterror%
echo uefisettings-shell: done
reset -s
