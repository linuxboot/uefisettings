echo -off
# The UEFI Shell boot of the scenario boot-manager, after the guest test boot_manager's
# before_shell; shell/boot-manager.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi variable get Boot0099
echo uefisettings-shell: step seeded-boot0099 %lasterror%
uefisettings.efi variable get Key0099
echo uefisettings-shell: step seeded-key0099 %lasterror%
echo uefisettings-shell: done
reset -s
