echo -off
# The boot of the scenario shell-callback-forms: publish-hiidb.efi callback-forms registers
# questions without a VarStore whose driver holds their value, which get reaches through the
# driver's Callback(), between reads of the form set's stores; shell/callback-forms.tsv holds
# the checks of the steps.
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
uefisettings.efi hii get --json "Callback value without read-back"
echo uefisettings-shell: step get-no-read-back %lasterror%
uefisettings.efi hii get --json "Callback value beside an unreachable store"
echo uefisettings-shell: step get-unreachable %lasterror%
uefisettings.efi hii get --json "Callback value without a driver"
echo uefisettings-shell: step get-driverless %lasterror%
echo uefisettings-shell: done
reset -s
