echo -off
# The second UEFI Shell boot of the scenario boot-manager, through Boot009B, which the first
# created, whose uefisettings.efi printed its usage and returned, so that the boot manager went on
# to the Shell of BootOrder; shell/boot-manager-next.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi variable get Boot009B
echo uefisettings-shell: step boot009b %lasterror%
uefisettings.efi variable get BootNext
echo uefisettings-shell: step boot-next-gone %lasterror%
echo uefisettings-shell: done
reset -s
