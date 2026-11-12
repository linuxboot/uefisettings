echo -off
# The boot of the scenario shell-undeclared-password: publish-hiidb.efi undeclared-password-forms
# registers, for one device path, a package list with a PASSWORD of VarStoreId 9, which no VarStore
# of its form package declares, beside the NUMERIC "Undeclared backing setting", of the x-UEFI-ns
# keyword UndeclaredSetting, over bytes 0..4 of UdBacking, and a package list with the NUMERIC
# "Undeclared other setting" over Other; vars/undeclared-password.json creates UdBacking, whose
# bytes 0..4 hold 0x7A4C19E3, and Other. shell/undeclared-password.tsv holds the checks of the
# steps.
fs0:
echo uefisettings-shell: start
dmpstore UdBacking -guid 8C78A505-BAA0-4C4A-869F-000000002301
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii get --json "Undeclared backing setting"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii get --json "Undeclared other setting"
echo uefisettings-shell: step get-other %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "PATH=0104140005a5788ca0ba4a4c869f0000000023047fff0400&KEYWORD=UndeclaredSetting"
echo uefisettings-shell: step keyword-get %lasterror%
uefisettings.efi hii keyword set --i-am-fine-to-brick-this-system "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f0000000023047fff0400&KEYWORD=UndeclaredSetting&VALUE=00000001"
echo uefisettings-shell: step keyword-set %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Undeclared backing setting" 1
echo uefisettings-shell: step set-bypassed %lasterror%
dmpstore UdBacking -guid 8C78A505-BAA0-4C4A-869F-000000002301
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
