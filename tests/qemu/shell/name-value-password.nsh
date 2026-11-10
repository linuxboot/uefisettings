echo -off
# The boot of the scenario shell-name-value-password: publish-hiidb.efi name-value-password-forms
# registers, for one device path, a package list whose PASSWORD is on the name "Pin" of a
# VARSTORE_NAME_VALUE, beside the NUMERIC "Backing setting", of the x-UEFI-ns keyword
# BackingSetting, over bytes 0..4 of NvBacking, and a package list with the NUMERIC
# "Other setting" over Other; vars/name-value-password.json creates NvBacking, whose bytes 0..4
# hold 0x7A5BC3E1, and Other. shell/name-value-password.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
dmpstore NvBacking -guid 8C78A505-BAA0-4C4A-869F-000000001F02
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii get --json "Backing setting"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii get --json "Other setting"
echo uefisettings-shell: step get-other %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "PATH=0104140005a5788ca0ba4a4c869f000000001f057fff0400&KEYWORD=BackingSetting"
echo uefisettings-shell: step keyword-get %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Backing setting" 1
echo uefisettings-shell: step set-bypassed %lasterror%
dmpstore NvBacking -guid 8C78A505-BAA0-4C4A-869F-000000001F02
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
