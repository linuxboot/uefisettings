echo -off
# The first boot of the scenario shell-global-variables; shell/global-variables.tsv holds the
# checks of its steps. dmpstore without arguments dumps the variables of EFI_GLOBAL_VARIABLE,
# which no refusal may change.
fs0:
echo uefisettings-shell: start
dmpstore
echo uefisettings-shell: step before %lasterror%
uefisettings.efi variable set BootNext Boot1234
echo uefisettings-shell: step boot-next-absent %lasterror%
uefisettings.efi variable set BootOrder Boot0000,Boot0000
echo uefisettings-shell: step boot-order-twice %lasterror%
uefisettings.efi variable set PlatformLang xx-XX
echo uefisettings-shell: step platform-lang-unsupported %lasterror%
uefisettings.efi variable set SetupMode 0
echo uefisettings-shell: step setup-mode %lasterror%
dmpstore
echo uefisettings-shell: step after %lasterror%
uefisettings.efi variable set Timeout 9
echo uefisettings-shell: step timeout %lasterror%
uefisettings.efi variable get Timeout
echo uefisettings-shell: step timeout-get %lasterror%
uefisettings.efi variable set PlatformLang fr-FR
echo uefisettings-shell: step platform-lang %lasterror%
uefisettings.efi variable set OsIndications none
echo uefisettings-shell: step os-indications %lasterror%
echo uefisettings-shell: done
reset -s
