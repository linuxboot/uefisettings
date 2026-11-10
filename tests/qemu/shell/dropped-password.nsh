echo -off
# The boot of the scenario shell-dropped-password: publish-hiidb.efi dropped-password-forms
# registers two form sets on the variable UefisettingsDropped, which
# tests/qemu/vars/dropped-password.json creates with 20 bytes of 0xAA, standing for a password,
# and then 1; uefisettings ignores the second form set, which holds the PASSWORD.
# shell/dropped-password.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Shared setting"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore UefisettingsDropped -guid 8C78A505-BAA0-4C4A-869F-000000000F02
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "Shared setting" 0
echo uefisettings-shell: step set %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Shared setting" 0
echo uefisettings-shell: step set-bypassed %lasterror%
dmpstore UefisettingsDropped -guid 8C78A505-BAA0-4C4A-869F-000000000F02
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
