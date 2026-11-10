echo -off
# The boot of the scenario shell-password: publish-hiidb.efi password-forms registers forms
# with AMI's setup password layout next to DriverSample's, and forms whose PASSWORD keeps the
# plaintext password "Sesame" in PlaintextPassword, which it creates, with a NUMERIC over
# that password and one beside it; tests/qemu/vars/amitse-setup.json creates AMITSESetup with
# 80 bytes of 0xAA, standing for passwords, and then 1; shell/password.tsv holds the checks
# of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Quiet Boot"
echo uefisettings-shell: step get-password-store %lasterror%
uefisettings.efi hii get --json "Password prefix as a number"
echo uefisettings-shell: step get-over-password %lasterror%
uefisettings.efi get --json "Password prefix as a number"
echo uefisettings-shell: step top-get-over-password %lasterror%
uefisettings.efi hii get --json "Setting beside the password"
echo uefisettings-shell: step get-beside-password %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
dmpstore AMITSESetup -guid 8C78A505-BAA0-4C4A-869F-000000000101
echo uefisettings-shell: step dmpstore-amitse-before %lasterror%
dmpstore PlaintextPassword -guid 8C78A505-BAA0-4C4A-869F-000000001101
echo uefisettings-shell: step dmpstore-plaintext-before %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 30
echo uefisettings-shell: step set-refused %lasterror%
uefisettings.efi set --json "How old are you? (Step)" 30
echo uefisettings-shell: step top-set-refused %lasterror%
uefisettings.efi hii set --json --bypass-setup-password "How old are you? (Step)" 30
echo uefisettings-shell: step set-removed-flag %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "How old are you? (Step)" 30
echo uefisettings-shell: step set-bypassed %lasterror%
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get-bypassed %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Password prefix as a number" 1
echo uefisettings-shell: step set-over-password %lasterror%
uefisettings.efi set --json --i-am-fine-to-brick-this-system "Password prefix as a number" 1
echo uefisettings-shell: step top-set-over-password %lasterror%
dmpstore PlaintextPassword -guid 8C78A505-BAA0-4C4A-869F-000000001101
echo uefisettings-shell: step dmpstore-plaintext-after %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Quiet Boot" Disabled
echo uefisettings-shell: step set-password-store %lasterror%
uefisettings.efi set --json --i-am-fine-to-brick-this-system "Quiet Boot" Disabled
echo uefisettings-shell: step top-set-password-store %lasterror%
dmpstore ConOutDev -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step dmpstore-volatile-before %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Volatile setting" 1
echo uefisettings-shell: step set-volatile %lasterror%
dmpstore ConOutDev -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step dmpstore-volatile-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system --allow-volatile "Volatile setting" 3
echo uefisettings-shell: step set-volatile-allowed %lasterror%
dmpstore ConOutDev -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step dmpstore-volatile-after %lasterror%
uefisettings.efi hii get --json "Password prefix as a number" >v captured
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
