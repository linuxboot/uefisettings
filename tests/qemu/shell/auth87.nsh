echo -off
# The boot of the scenario shell-auth87, where EnhancedAuthData and EnhancedAuthRefused have the
# attributes 0x87, among them EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (0x80); shell/auth87.tsv
# holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore EnhancedAuthData -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii get --json "Value behind accepted metadata"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii set --json "Value behind accepted metadata" 44
echo uefisettings-shell: step set %lasterror%
uefisettings.efi set --json "Value behind accepted metadata" 44
echo uefisettings-shell: step top-set %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Value behind accepted metadata" 44
echo uefisettings-shell: step set-bypass %lasterror%
dmpstore EnhancedAuthData -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-after %lasterror%
uefisettings.efi hii variable-info EnhancedAuthData 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step variable-info %lasterror%
uefisettings.efi hii get --json "Value behind refused metadata"
echo uefisettings-shell: step get-refused %lasterror%
uefisettings.efi hii set --json "Value behind refused metadata" 44
echo uefisettings-shell: step set-refused %lasterror%
echo uefisettings-shell: done
reset -s
