echo -off
# The boot of the scenario shell-password: publish-hiidb.efi password-forms registers forms
# with AMI's setup password layout next to DriverSample's, and tests/qemu/vars/amitse-setup.json
# creates AMITSESetup with 80 bytes of 0xAA, standing for passwords, and then 1;
# shell/password.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Quiet Boot"
echo uefisettings-shell: step get-password-store %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore AMITSESetup -guid 8C78A505-BAA0-4C4A-869F-000000000101
echo uefisettings-shell: step dmpstore-amitse-before %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 30
echo uefisettings-shell: step set-refused %lasterror%
uefisettings.efi set --json "How old are you? (Step)" 30
echo uefisettings-shell: step top-set-refused %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-refused %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "How old are you? (Step)" 30
echo uefisettings-shell: step set-bypassed %lasterror%
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get-bypassed %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Quiet Boot" Disabled
echo uefisettings-shell: step set-password-store %lasterror%
uefisettings.efi set --json --bypass-setup-password "Quiet Boot" Disabled
echo uefisettings-shell: step top-set-password-store %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "Volatile setting" 1
echo uefisettings-shell: step set-volatile %lasterror%
uefisettings.efi hii get --json "Quiet Boot" >v captured
echo uefisettings-shell: step capture %lasterror%
set
echo uefisettings-shell: step variables %lasterror%
dmpstore AMITSESetup -guid 8C78A505-BAA0-4C4A-869F-000000000101
echo uefisettings-shell: step dmpstore-amitse-after %lasterror%
uefisettings.efi hii variable-info AMITSESetup 8C78A505-BAA0-4C4A-869F-000000000101
echo uefisettings-shell: step variable-info %lasterror%
uefisettings.efi hii variable-info NoSuchVariable 8C78A505-BAA0-4C4A-869F-000000000101
echo uefisettings-shell: step variable-info-missing %lasterror%
uefisettings.efi hii variable-info AMITSESetup 8C78A505-BAA0-4C4A-869F
echo uefisettings-shell: step variable-info-bad-guid %lasterror%
uefisettings.efi variable info AMITSESetup 8C78A505-BAA0-4C4A-869F-000000000101
echo uefisettings-shell: step variable-info-command %lasterror%
uefisettings.efi variable info NoSuchVariable 8C78A505-BAA0-4C4A-869F-000000000101
echo uefisettings-shell: step variable-info-command-missing %lasterror%
echo uefisettings-shell: done
reset -s
