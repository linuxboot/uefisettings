echo -off
# The boot of the scenario shell-short-var-store: publish-hiidb.efi short-var-store-forms
# registers questions on a VARSTORE_EFI of the form before UEFI 2.3.1, each on the EFI variable
# of its VarName, which tests/qemu/vars/short-var-store.json creates: ShortVarA holds 5,
# ShortVarB and ShortVarC 0, and ShortVarPw, the variable of a PASSWORD, 20 bytes of 0xAA,
# standing for a password, but not ShortVarD, which set creates; shell/short-var-store.tsv holds
# the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Short numeric"
echo uefisettings-shell: step get-numeric %lasterror%
uefisettings.efi hii get --json "Short one-of"
echo uefisettings-shell: step get-one-of %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore ShortVarA -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-a-before %lasterror%
dmpstore ShortVarPw -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-pw-before %lasterror%
uefisettings.efi hii set --json "Short numeric" 9
echo uefisettings-shell: step set-refused %lasterror%
dmpstore ShortVarA -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-a-refused %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Short checkbox" 1
echo uefisettings-shell: step set-suppressed %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Short numeric" 9
echo uefisettings-shell: step set-numeric %lasterror%
dmpstore ShortVarA -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-a-after %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Short checkbox" 1
echo uefisettings-shell: step set-checkbox %lasterror%
uefisettings.efi hii get --json "Short one-of"
echo uefisettings-shell: step get-one-of-after %lasterror%
dmpstore ShortVarB -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-b-after %lasterror%
dmpstore ShortVarC -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-c-after %lasterror%
dmpstore ShortVarPw -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-pw-after %lasterror%
dmpstore ShortVarD -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-d-before %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Short created" 513
echo uefisettings-shell: step set-created %lasterror%
dmpstore ShortVarD -guid 8C78A505-BAA0-4C4A-869F-000000000B01
echo uefisettings-shell: step dmpstore-d-after %lasterror%
uefisettings.efi hii get --json "Short created"
echo uefisettings-shell: step get-created %lasterror%
echo uefisettings-shell: done
reset -s
