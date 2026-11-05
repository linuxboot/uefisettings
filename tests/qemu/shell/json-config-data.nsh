echo -off
# The boot of the scenario shell-json-config-data: uefisettings.efi prints the JSON configuration
# table that publish-hiidb.efi json-config-data installs. shell/json-config-data.tsv holds the
# checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi capsule config-data
echo uefisettings-shell: step config-data %lasterror%
echo uefisettings-shell: done
reset -s
