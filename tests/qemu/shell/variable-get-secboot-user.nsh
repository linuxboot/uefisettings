echo -off
# The boot of the scenario shell-variable-get-secboot-user, on the secboot firmware with
# per-run PK, KEK and db enrolled and SecureBootEnable cleared: User Mode with Secure Boot off.
# shell/variable-get-secboot-user.tsv holds the checks of its steps.
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
uefisettings.efi variable get PK
echo uefisettings-shell: step pk %lasterror%
uefisettings.efi variable get db
echo uefisettings-shell: step db %lasterror%
echo uefisettings-shell: done
reset -s
