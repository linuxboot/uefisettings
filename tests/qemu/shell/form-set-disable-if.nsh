echo -off
# The boot of the scenario shell-form-set-disable-if: publish-hiidb.efi form-set-disable-if-forms
# registers a form set on the variable UefisettingsFormSetDisableIf, which
# tests/qemu/vars/form-set-disable-if.json creates with Gate 0, Hidden 1, Shown 2, After 3 and
# Later 4, 3 bytes of 0, then 16 bytes of 0xBB, standing for a password. Its first form keeps Gate,
# Shown, in a SUPPRESS_IF on Hidden holding 1, and O, over the password; a true DISABLE_IF outside
# forms holds the form of Hidden and of the PASSWORD at bytes 8 to 23; a DISABLE_IF on Gate holds
# the form of After; and a false DISABLE_IF holds a true SUPPRESS_IF, then the form of Later.
# shell/form-set-disable-if.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii list-questions --json --include grayed-out,suppressed,disabled
echo uefisettings-shell: step list-questions-all %lasterror%
uefisettings.efi hii get --json Hidden
echo uefisettings-shell: step get-hidden %lasterror%
uefisettings.efi hii get --json --include grayed-out,suppressed,disabled Hidden
echo uefisettings-shell: step get-hidden-all %lasterror%
uefisettings.efi hii get --json Shown
echo uefisettings-shell: step get-shown %lasterror%
uefisettings.efi hii get --json After
echo uefisettings-shell: step get-after %lasterror%
uefisettings.efi hii get --json Later
echo uefisettings-shell: step get-later %lasterror%
uefisettings.efi hii get --json O
echo uefisettings-shell: step get-o %lasterror%
dmpstore UefisettingsFormSetDisableIf -guid 8C78A505-BAA0-4C4A-869F-000000002401
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json --include disabled After 9
echo uefisettings-shell: step set-flagless %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system --include grayed-out,suppressed,disabled Hidden 5
echo uefisettings-shell: step set-hidden %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system After 9
echo uefisettings-shell: step set-after-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system Later 7
echo uefisettings-shell: step set-later-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system --include disabled O 5
echo uefisettings-shell: step set-o %lasterror%
dmpstore UefisettingsFormSetDisableIf -guid 8C78A505-BAA0-4C4A-869F-000000002401
echo uefisettings-shell: step dmpstore-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system --include disabled After 9
echo uefisettings-shell: step set-after %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system --include disabled Later 7
echo uefisettings-shell: step set-later %lasterror%
dmpstore UefisettingsFormSetDisableIf -guid 8C78A505-BAA0-4C4A-869F-000000002401
echo uefisettings-shell: step dmpstore-after %lasterror%
uefisettings.efi hii get --json --include disabled After
echo uefisettings-shell: step get-after-written %lasterror%
echo uefisettings-shell: done
reset -s
