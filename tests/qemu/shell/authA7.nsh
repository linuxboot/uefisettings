echo -off
# The boot of the scenario shell-authA7, where MyIfrNVData has the attributes 0xA7, among
# them EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (0x80); shell/authA7.tsv holds the checks
# of its steps.
fs0:
echo uefisettings-shell: start
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 44
echo uefisettings-shell: step set %lasterror%
uefisettings.efi set --json "How old are you? (Step)" 44
echo uefisettings-shell: step top-set %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "How old are you? (Step)" 44
echo uefisettings-shell: step set-bypass %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
