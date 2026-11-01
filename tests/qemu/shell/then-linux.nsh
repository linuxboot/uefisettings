echo -off
# The third boot of the scenario shell-driver-sample: uefisettings.efi runs, then the shell
# starts Linux, whose ExitBootServices() signals any event that uefisettings.efi left open
# after it exited. run.sh replaces @LINUX@ with the kernel and its command line, and fails the
# boot unless the guest test passes; shell/then-linux.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Activate this check box"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 43
echo uefisettings-shell: step set %lasterror%
uefisettings.efi bogus-subcommand
echo uefisettings-shell: step usage-error %lasterror%
echo uefisettings-shell: done
@LINUX@
reset -s
