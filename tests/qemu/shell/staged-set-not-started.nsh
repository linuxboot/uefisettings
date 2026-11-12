echo -off
# The third boot of the scenario staged-set: the firmware finds no image for the Boot#### of
# the set that Linux staged, as Linux deleted it, and starts the UEFI Shell, which reads the
# question of that set. shell/staged-set-not-started.tsv holds the checks.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Callback value beside stores"
echo uefisettings-shell: step get-unapplied %lasterror%
echo uefisettings-shell: done
reset -s
