echo -off
# The second boot of the scenario shell-parity, after the Linux boot of
# guest/tests/hii_shell_parity.rs on the same variables; shell/list-questions.tsv compares
# the questions, listed in every state on both, and the variables of DriverSample.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii list-questions --json --include grayed-out,suppressed,disabled
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi variable list --guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step variable-list %lasterror%
echo uefisettings-shell: done
reset -s
