echo -off
# The boot of the scenarios shell-json-config-data-past-region, -boot-services and -mmio:
# uefisettings.efi refuses the JSON configuration table of publish-hiidb.efi
# json-config-data-past-region, json-config-data-boot-services or json-config-data-mmio.
# shell/json-config-data-refused.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi capsule config-data
echo uefisettings-shell: step config-data %lasterror%
echo uefisettings-shell: done
reset -s
