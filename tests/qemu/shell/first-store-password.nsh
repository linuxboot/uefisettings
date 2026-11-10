echo -off
# The boot of the scenario shell-first-store-password: publish-hiidb.efi
# first-store-password-forms creates FirstStore, whose bytes 0..16 hold the password "First" and
# byte 16 holds 5, and PasswordStore, and registers forms whose first form set declares FirstStore
# for VarStoreId 1, the first VarStore of that id in the form package, with NUMERICs over and
# beside the password's bytes there, and whose second form set has a PASSWORD of VarStoreId 1 on
# PasswordStore. shell/first-store-password.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "First store password prefix as a number"
echo uefisettings-shell: step get-over-password %lasterror%
uefisettings.efi get --json "First store password prefix as a number"
echo uefisettings-shell: step top-get-over-password %lasterror%
uefisettings.efi hii get --json "Setting beside the first store password"
echo uefisettings-shell: step get-beside-password %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore FirstStore -guid 8C78A505-BAA0-4C4A-869F-000000001D01
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "First store password prefix as a number" 1
echo uefisettings-shell: step set-over-password %lasterror%
uefisettings.efi set --json --i-am-fine-to-brick-this-system "First store password prefix as a number" 1
echo uefisettings-shell: step top-set-over-password %lasterror%
dmpstore FirstStore -guid 8C78A505-BAA0-4C4A-869F-000000001D01
echo uefisettings-shell: step dmpstore-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Setting beside the first store password" 6
echo uefisettings-shell: step set-beside-password %lasterror%
dmpstore FirstStore -guid 8C78A505-BAA0-4C4A-869F-000000001D01
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
