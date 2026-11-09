echo -off
# The boot of the scenario shell-nested-password: publish-hiidb.efi nested-password-forms
# creates NestedPassword, which keeps the plaintext password "Kumquat" and then 1, and
# NestedChoice, which holds 0, and registers forms whose VarStores sit in the scopes of
# FormSet-level conditions: NestedPassword under a SUPPRESS_IF, with a PASSWORD, a NUMERIC over
# its bytes and a CHECKBOX beside it; NestedChoiceDecoy under a DISABLE_IF whose condition is
# TRUE and NestedChoice under one whose condition is FALSE, both of VarStoreId 2, with a
# CHECKBOX; a second form set declares NestedPassword directly, with a NUMERIC over the
# password's bytes. shell/nested-password.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Nested password prefix as a number"
echo uefisettings-shell: step get-over-password %lasterror%
uefisettings.efi hii get --json "Nested password prefix from another form set"
echo uefisettings-shell: step get-over-password-elsewhere %lasterror%
uefisettings.efi hii get --json "Nested setting beside the password"
echo uefisettings-shell: step get-beside-password %lasterror%
uefisettings.efi hii get --json "Nested choice"
echo uefisettings-shell: step get-choice %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore NestedPassword -guid 8C78A505-BAA0-4C4A-869F-000000001C01
echo uefisettings-shell: step dmpstore-password-before %lasterror%
dmpstore NestedChoice -guid 8C78A505-BAA0-4C4A-869F-000000001C01
echo uefisettings-shell: step dmpstore-choice-before %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Nested password prefix as a number" 1
echo uefisettings-shell: step set-over-password %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Nested password prefix from another form set" 1
echo uefisettings-shell: step set-over-password-elsewhere %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Nested setting beside the password" 0
echo uefisettings-shell: step set-beside-password %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Nested choice" 1
echo uefisettings-shell: step set-choice %lasterror%
dmpstore NestedPassword -guid 8C78A505-BAA0-4C4A-869F-000000001C01
echo uefisettings-shell: step dmpstore-password-after %lasterror%
dmpstore NestedChoice -guid 8C78A505-BAA0-4C4A-869F-000000001C01
echo uefisettings-shell: step dmpstore-choice-after %lasterror%
dmpstore NestedChoiceDecoy -guid 8C78A505-BAA0-4C4A-869F-000000001C01
echo uefisettings-shell: step dmpstore-decoy %lasterror%
echo uefisettings-shell: done
reset -s
