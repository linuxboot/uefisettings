echo -off
# The boot of the scenario shell-formset-skip: publish-hiidb.efi formset-skip-forms registers
# three form sets on the variable UefisettingsFormSetSkip, which tests/qemu/vars/formset-skip.json
# creates with 20 bytes of 0xAA, standing for a password, then 1 and 3; uefisettings ignores the
# second form set, which holds the PASSWORD, and reads the third.
# shell/formset-skip.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Third setting"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
dmpstore UefisettingsFormSetSkip -guid 8C78A505-BAA0-4C4A-869F-000000001203
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "Third setting" 4
echo uefisettings-shell: step set %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Third setting" 4
echo uefisettings-shell: step set-bypassed %lasterror%
dmpstore UefisettingsFormSetSkip -guid 8C78A505-BAA0-4C4A-869F-000000001203
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
