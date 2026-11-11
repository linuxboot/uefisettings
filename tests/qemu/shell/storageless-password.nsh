echo -off
# The boot of the scenario shell-storageless-password: publish-hiidb.efi storageless-password-forms
# registers, for one device path, a package list with two PASSWORDs of VarStoreId 0, one with
# EFI_IFR_FLAG_CALLBACK and one without, beside the NUMERIC "Storageless backing setting", of the
# x-UEFI-ns keyword StoragelessSetting, over bytes 0..4 of SlBacking, and a package list with the
# NUMERIC "Storageless other setting" over Other; vars/storageless-password.json creates SlBacking,
# whose bytes 0..4 hold 0x3E17A95C, and Other. shell/storageless-password.tsv holds the checks of
# the steps.
fs0:
echo uefisettings-shell: start
dmpstore SlBacking -guid 8C78A505-BAA0-4C4A-869F-000000002101
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii get --json "Storageless backing setting"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii get --json "Storageless other setting"
echo uefisettings-shell: step get-other %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "PATH=0104140005a5788ca0ba4a4c869f0000000021047fff0400&KEYWORD=StoragelessSetting"
echo uefisettings-shell: step keyword-get %lasterror%
uefisettings.efi hii keyword set --i-am-fine-to-brick-this-system "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f0000000021047fff0400&KEYWORD=StoragelessSetting&VALUE=00000001"
echo uefisettings-shell: step keyword-set %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Storageless backing setting" 1
echo uefisettings-shell: step set-bypassed %lasterror%
dmpstore SlBacking -guid 8C78A505-BAA0-4C4A-869F-000000002101
echo uefisettings-shell: step dmpstore-after %lasterror%
echo uefisettings-shell: done
reset -s
