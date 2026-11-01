echo -off
# The second boot of the scenario shell-driver-sample, on the variables of the first;
# shell/driver-sample-reboot.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get-numeric %lasterror%
uefisettings.efi hii get --json "Activate this check box"
echo uefisettings-shell: step get-check-box %lasterror%
uefisettings.efi hii get --json "How tall are you? (Hex)"
echo uefisettings-shell: step get-efi-var %lasterror%
echo uefisettings-shell: done
reset -s
