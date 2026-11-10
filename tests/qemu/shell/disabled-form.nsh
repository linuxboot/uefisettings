echo -off
# The boot of the scenario shell-disabled-form: publish-hiidb.efi disabled-form-forms registers a
# form set on the variable UefisettingsDisabledForm, which tests/qemu/vars/disabled-form.json
# creates with 20 bytes of 0xBB, standing for a password, then 1 and 5. Its first form keeps
# "Live setting" at byte 20 and "Over password" at byte 0; its second, which a CHECKBOX op shorter
# than its minimum disables, holds "Disabled setting" at byte 21 and the PASSWORD at bytes 0 to
# 19. shell/disabled-form.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Live setting"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii get --json "Over password"
echo uefisettings-shell: step get-over-password %lasterror%
uefisettings.efi hii get --json "Disabled setting"
echo uefisettings-shell: step get-disabled %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore UefisettingsDisabledForm -guid 8C78A505-BAA0-4C4A-869F-000000001231
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "Live setting" 2
echo uefisettings-shell: step set-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Disabled setting" 6
echo uefisettings-shell: step set-disabled %lasterror%
dmpstore UefisettingsDisabledForm -guid 8C78A505-BAA0-4C4A-869F-000000001231
echo uefisettings-shell: step dmpstore-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Live setting" 2
echo uefisettings-shell: step set-bypassed %lasterror%
dmpstore UefisettingsDisabledForm -guid 8C78A505-BAA0-4C4A-869F-000000001231
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
