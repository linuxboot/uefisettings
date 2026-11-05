echo -off
# The boot of the scenario shell-capsule: uefisettings.efi delivers the payloads of
# shell/capsule, which run.sh copies to the ESP's \capsule, through the firmware's
# QueryCapsuleCapabilities() and UpdateCapsule(). shell/capsule.tsv holds the checks of its
# steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi capsule deliver capsule\payload.json --capsule-id 1
echo uefisettings-shell: step deliver %lasterror%
uefisettings.efi capsule deliver capsule\empty.json --capsule-id 1
echo uefisettings-shell: step deliver-empty %lasterror%
uefisettings.efi capsule deliver capsule\missing.json --capsule-id 1
echo uefisettings-shell: step deliver-missing %lasterror%
echo uefisettings-shell: done
reset -s
