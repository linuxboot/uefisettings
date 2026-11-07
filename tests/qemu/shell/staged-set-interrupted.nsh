echo -off
# The fourth boot of the scenario staged-set: the firmware starts the Boot#### of the set that
# Linux staged, whose question's Callback(CHANGED) resets the platform before uefisettings.efi
# records any result; then the UEFI Shell reads that question. shell/staged-set-interrupted.tsv
# holds the checks.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Callback value resetting the platform"
echo uefisettings-shell: step get-partly-applied %lasterror%
echo uefisettings-shell: done
reset -s
