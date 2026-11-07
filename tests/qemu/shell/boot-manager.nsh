echo -off
# The UEFI Shell boot of the scenario boot-manager, after the guest test boot_manager's
# before_shell; shell/boot-manager.tsv holds the checks of its steps. dmpstore without arguments
# dumps the variables of EFI_GLOBAL_VARIABLE, which no refusal may change.
fs0:
echo uefisettings-shell: start
uefisettings.efi variable get Boot0099
echo uefisettings-shell: step seeded-boot0099 %lasterror%
uefisettings.efi variable get Key0099
echo uefisettings-shell: step seeded-key0099 %lasterror%
dmpstore
echo uefisettings-shell: step before-refusals %lasterror%
uefisettings.efi variable set-attributes PlatformRecovery0000 --set active
echo uefisettings-shell: step platform-recovery %lasterror%
uefisettings.efi variable set-attributes OsRecovery0000 --set active
echo uefisettings-shell: step os-recovery %lasterror%
uefisettings.efi variable set-attributes Boot1234 --set active
echo uefisettings-shell: step absent %lasterror%
uefisettings.efi variable set-attributes Boot0099 --set active --clear active
echo uefisettings-shell: step set-and-clear %lasterror%
dmpstore
echo uefisettings-shell: step after-refusals %lasterror%
uefisettings.efi variable set-attributes Boot0099 --clear active
echo uefisettings-shell: step inactive-boot0099 %lasterror%
uefisettings.efi variable get Key0099
echo uefisettings-shell: step inactive-key0099 %lasterror%
uefisettings.efi variable set-attributes Boot0099 --set active
echo uefisettings-shell: step active-boot0099 %lasterror%
uefisettings.efi variable get Key0099
echo uefisettings-shell: step active-key0099 %lasterror%
uefisettings.efi variable set-attributes Driver0000 --set force-reconnect
echo uefisettings-shell: step driver-force-reconnect %lasterror%
uefisettings.efi variable set-attributes Driver0000 --clear force-reconnect
echo uefisettings-shell: step driver-reconnect-cleared %lasterror%
echo uefisettings-shell: done
reset -s
