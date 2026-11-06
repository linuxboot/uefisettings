echo -off
# The boot of the scenario shell-callback-forms: publish-hiidb.efi callback-forms registers
# questions without a VarStore whose driver holds their value, which get and set reach through
# the driver's Callback(), between reads of the form set's stores; shell/callback-forms.tsv
# holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
uefisettings.efi hii get --json --no-efivars "Callback value beside stores"
echo uefisettings-shell: step get-no-efivars %lasterror%
uefisettings.efi hii get --json "Callback value beside stores"
echo uefisettings-shell: step get-beside %lasterror%
uefisettings.efi hii set --json "Callback value beside stores" On
echo uefisettings-shell: step set-beside %lasterror%
uefisettings.efi hii get --json "Callback value beside stores"
echo uefisettings-shell: step get-beside-after %lasterror%
dmpstore CallbackStore -guid DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step efi-store-before %lasterror%
uefisettings.efi hii set --json "Callback value overwriting its EFI variable store" On
echo uefisettings-shell: step set-efi-store %lasterror%
dmpstore CallbackStore -guid DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step efi-store-after %lasterror%
uefisettings.efi hii get --json "Buffer setting"
echo uefisettings-shell: step buffer-before %lasterror%
uefisettings.efi hii set --json "Callback value overwriting its Buffer store" On
echo uefisettings-shell: step set-buffer-store %lasterror%
uefisettings.efi hii get --json "Buffer setting"
echo uefisettings-shell: step buffer-after %lasterror%
uefisettings.efi hii set --json "Callback value refused in CHANGING" On
echo uefisettings-shell: step set-refused-in-changing %lasterror%
uefisettings.efi hii set --json "Callback value failing in CHANGED" On
echo uefisettings-shell: step set-failing-in-changed %lasterror%
uefisettings.efi hii set --json "Callback value asking for a save" On
echo uefisettings-shell: step set-save %lasterror%
uefisettings.efi hii set --json "Callback value asking for a reconnection" On
echo uefisettings-shell: step set-reconnect %lasterror%
uefisettings.efi hii set --json "Transient callback value" On
echo uefisettings-shell: step set-transient %lasterror%
uefisettings.efi hii set --json "Callback value without read-back" On
echo uefisettings-shell: step set-no-read-back %lasterror%
uefisettings.efi hii get --json "Callback value without read-back"
echo uefisettings-shell: step get-no-read-back %lasterror%
uefisettings.efi hii set --json "Callback value asking for a reset" On
echo uefisettings-shell: step set-reset %lasterror%
uefisettings.efi hii get --json "Callback value beside an unreachable store"
echo uefisettings-shell: step get-unreachable %lasterror%
uefisettings.efi hii set --json "Callback value beside an unreachable store" On
echo uefisettings-shell: step set-unreachable %lasterror%
uefisettings.efi hii get --json "Callback value without a driver"
echo uefisettings-shell: step get-driverless %lasterror%
uefisettings.efi hii set --json "Callback value without a driver" On
echo uefisettings-shell: step set-driverless %lasterror%
echo uefisettings-shell: done
reset -s
