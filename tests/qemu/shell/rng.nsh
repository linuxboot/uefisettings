echo -off
# The boot of the scenario shell-rng, whose options add a virtio-rng device: its driver,
# VirtioRngDxe, gives the firmware EFI_RNG_PROTOCOL, which the scenarios without the device
# lack. shell/rng.tsv holds the checks of its step.
fs0:
echo uefisettings-shell: start
dh -p 3152BCA5-EADE-433D-862E-C01CDC291F44
echo uefisettings-shell: step rng-handles %lasterror%
echo uefisettings-shell: done
reset -s
