echo -off
# The boot of the scenario shell-secboot-user, on the secboot firmware with per-run PK, KEK
# and db enrolled and SecureBootEnable cleared: User Mode with Secure Boot off. publish-hiidb
# set-auth-variables ran before the Shell and left %AuthProbeLog%; shell/secboot-user.tsv
# holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore SetupMode -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step setup-mode %lasterror%
dmpstore SecureBoot -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step secure-boot %lasterror%
echo %AuthProbeLog%
echo uefisettings-shell: step auth-probe-log %lasterror%
echo uefisettings-shell: done
reset -s
