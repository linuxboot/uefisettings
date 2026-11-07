echo -off
# The boot of the scenario shell-variable-get, on the default firmware, whose variable store
# holds no Secure Boot variables; shell/variable-get.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi variable get Timeout
echo uefisettings-shell: step timeout %lasterror%
uefisettings.efi variable get BootOrder
echo uefisettings-shell: step boot-order %lasterror%
uefisettings.efi variable get SecureBoot
echo uefisettings-shell: step secure-boot %lasterror%
uefisettings.efi variable get SetupMode
echo uefisettings-shell: step setup-mode %lasterror%
uefisettings.efi variable get Boot0001
echo uefisettings-shell: step boot0001 %lasterror%
uefisettings.efi variable get Boot0002
echo uefisettings-shell: step boot0002 %lasterror%
uefisettings.efi variable get Key0000
echo uefisettings-shell: step key0000 %lasterror%
uefisettings.efi variable get ConOut
echo uefisettings-shell: step con-out %lasterror%
uefisettings.efi variable get Boot001
echo uefisettings-shell: step unknown %lasterror%
echo uefisettings-shell: done
reset -s
