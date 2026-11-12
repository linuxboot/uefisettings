echo -off
# The first UEFI Shell boot of the scenario boot-manager, after the guest test boot_manager's
# before_shell, through Boot009A, which BootNext names; shell/boot-manager.tsv holds the checks
# of its steps. dmpstore without arguments dumps the variables of EFI_GLOBAL_VARIABLE, which no
# refusal may change.
fs0:
echo uefisettings-shell: start
uefisettings.efi variable get Boot009A
echo uefisettings-shell: step boot009a %lasterror%
uefisettings.efi variable get BootNext
echo uefisettings-shell: step boot-next-gone %lasterror%
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
uefisettings.efi variable create-load-option Boot0099 --description again --device-path \missing-99.efi
echo uefisettings-shell: step create-existing %lasterror%
uefisettings.efi variable set-device-path ConOutDev --device-path Pci(0x1,0x0)
echo uefisettings-shell: step con-out-dev %lasterror%
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
uefisettings.efi variable create-load-option Boot009B --description "uefisettings again" --device-path \uefisettings.efi
echo uefisettings-shell: step created-boot009b %lasterror%
uefisettings.efi variable set BootNext Boot009B
echo uefisettings-shell: step boot-next %lasterror%
uefisettings.efi variable create-key Key0099 --boot Boot0099 --key F2
echo uefisettings-shell: step key-existing %lasterror%
uefisettings.efi variable create-key Key009C --boot Boot009B --modifiers alt --key F11
echo uefisettings-shell: step key-taken %lasterror%
uefisettings.efi variable create-key Key009B --boot Boot009B --modifiers shift --key F12
echo uefisettings-shell: step created-key009b %lasterror%
echo uefisettings-shell: done
reset -s
