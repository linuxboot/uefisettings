echo -off
# The second boot of the scenario staged-set: before the UEFI Shell, the firmware starts the
# Boot#### of the set that Linux staged, whose uefisettings.efi applies it and resets the
# platform; then the Shell reads the questions that it set. shell/staged-set-applied.tsv holds
# the checks.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Callback value beside stores"
echo uefisettings-shell: step get-applied %lasterror%
uefisettings.efi hii get --json "Callback value refused in CHANGING"
echo uefisettings-shell: step get-refused %lasterror%
echo uefisettings-shell: done
reset -s
