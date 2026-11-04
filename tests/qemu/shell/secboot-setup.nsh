echo -off
# The boot of the scenario shell-secboot-setup, on the secboot firmware with a template copy
# of its variable store: Setup Mode. shell/secboot-setup.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore SetupMode -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step setup-mode %lasterror%
dmpstore SecureBoot -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step secure-boot %lasterror%
echo uefisettings-shell: done
reset -s
