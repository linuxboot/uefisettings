echo -off
# The boot of the scenario shell-outside-form-set-password: publish-hiidb.efi
# outside-form-set-password-forms creates OutsidePassword, whose bytes 0..16 hold the password
# "Outside" and byte 16 holds 5, and registers forms whose PASSWORD, outside any form set, names
# its VarStoreId; the form set's NUMERICs read over and beside the password's bytes.
# shell/outside-form-set-password.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Outside password prefix as a number"
echo uefisettings-shell: step get-over-password %lasterror%
uefisettings.efi get --json "Outside password prefix as a number"
echo uefisettings-shell: step top-get-over-password %lasterror%
uefisettings.efi hii get --json "Setting beside the outside password"
echo uefisettings-shell: step get-beside-password %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore OutsidePassword -guid 8C78A505-BAA0-4C4A-869F-000000001B01
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "Setting beside the outside password" 6
echo uefisettings-shell: step set %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Setting beside the outside password" 6
echo uefisettings-shell: step set-bypassed %lasterror%
uefisettings.efi set --json --bypass-setup-password "Setting beside the outside password" 6
echo uefisettings-shell: step top-set-bypassed %lasterror%
dmpstore OutsidePassword -guid 8C78A505-BAA0-4C4A-869F-000000001B01
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
