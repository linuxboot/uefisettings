echo -off
# The boot of the scenarios shell-secure-boot-modes-setup and shell-secure-boot-modes-user, on
# the secboot firmware in Setup Mode and, with run.sh's PK, KEK and db enrolled, in User Mode; its
# edk2 creates no AuditMode or DeployedMode. variable set refuses AuditMode and DeployedMode, with
# --i-am-fine-to-brick-this-system and without, before any write, as the firmware lacks the mode
# variables, and --enter-audit-mode-clearing-pk and --enter-deployed-mode-irreversibly, which the
# flag replaced, as unexpected arguments. dmpstore without arguments dumps the variables of
# EFI_GLOBAL_VARIABLE, PK among them, which no refusal may change. shell/secure-boot-modes.tsv holds
# the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore
echo uefisettings-shell: step before %lasterror%
dmpstore PK -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step pk-before %lasterror%
uefisettings.efi variable set AuditMode 1
echo uefisettings-shell: step audit-mode-unflagged %lasterror%
uefisettings.efi variable set AuditMode 1 --enter-audit-mode-clearing-pk
echo uefisettings-shell: step audit-mode-removed-flag %lasterror%
uefisettings.efi variable set AuditMode 1 --i-am-fine-to-brick-this-system
echo uefisettings-shell: step audit-mode %lasterror%
uefisettings.efi variable set DeployedMode 1
echo uefisettings-shell: step deployed-mode-unflagged %lasterror%
uefisettings.efi variable set DeployedMode 1 --enter-deployed-mode-irreversibly
echo uefisettings-shell: step deployed-mode-removed-flag %lasterror%
uefisettings.efi variable set DeployedMode 1 --i-am-fine-to-brick-this-system
echo uefisettings-shell: step deployed-mode %lasterror%
dmpstore PK -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step pk-after %lasterror%
dmpstore
echo uefisettings-shell: step after %lasterror%
echo uefisettings-shell: done
reset -s
