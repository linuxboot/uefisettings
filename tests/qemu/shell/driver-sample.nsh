echo -off
# The first boot of the scenario shell-driver-sample; run.sh copies this file to the ESP as
# startup.nsh, and shell/driver-sample.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Activate this check box"
echo uefisettings-shell: step get-check-box %lasterror%
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get-numeric %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 42
echo uefisettings-shell: step set-numeric %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-after %lasterror%
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get-numeric-after %lasterror%
uefisettings.efi hii get --json "How tall are you? (Hex)"
echo uefisettings-shell: step get-efi-var %lasterror%
uefisettings.efi hii set --json "How tall are you? (Hex)" 20
echo uefisettings-shell: step set-efi-var %lasterror%
uefisettings.efi hii get --json "How tall are you? (Hex)"
echo uefisettings-shell: step get-efi-var-after %lasterror%
dmpstore MyEfiVar -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-efi-var %lasterror%
uefisettings.efi hii get --json "No such question anywhere"
echo uefisettings-shell: step get-unknown %lasterror%
uefisettings.efi hii set --json "No such question anywhere" 1
echo uefisettings-shell: step set-unknown %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 250
echo uefisettings-shell: step set-out-of-range %lasterror%
uefisettings.efi bogus-subcommand
echo uefisettings-shell: step usage-error %lasterror%
uefisettings.efi hii set "How old are you? (Step)"
echo uefisettings-shell: step missing-value %lasterror%
uefisettings.efi hii extract-db hiidb.bin
echo uefisettings-shell: step extract-db %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-negatives %lasterror%
uefisettings.efi hii get --json "Activate this check box" >v captured
echo uefisettings-shell: step capture %lasterror%
set
echo uefisettings-shell: step variables %lasterror%
uefisettings.efi get --json "Activate this check box"
echo uefisettings-shell: step top-get %lasterror%
uefisettings.efi set --json "Activate this check box" 0
echo uefisettings-shell: step top-set %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
uefisettings.efi hii list-strings --json
echo uefisettings-shell: step list-strings %lasterror%
uefisettings.efi show-translations --json
echo uefisettings-shell: step show-translations %lasterror%
uefisettings.efi hii get --json --no-efivars "Activate this check box"
echo uefisettings-shell: step no-efivars %lasterror%
uefisettings.efi variable list
echo uefisettings-shell: step variable-list %lasterror%
uefisettings.efi variable list --guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step variable-list-guid %lasterror%
uefisettings.efi variable list --guid A04A27F4
echo uefisettings-shell: step variable-list-bad-guid %lasterror%
uefisettings.efi variable info MyIfrNVData A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step variable-info %lasterror%
uefisettings.efi --help
echo uefisettings-shell: step help %lasterror%
uefisettings.efi hii --help
echo uefisettings-shell: step hii-help %lasterror%
uefisettings.efi hii get --help
echo uefisettings-shell: step hii-get-help %lasterror%
uefisettings.efi hii set --help
echo uefisettings-shell: step hii-set-help %lasterror%
echo uefisettings-shell: done
reset -s
