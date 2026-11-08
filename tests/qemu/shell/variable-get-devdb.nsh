echo -off
# The boot of the scenario shell-variable-get-devdb, on the default firmware, whose variable
# store holds the devdb that vars/devdb.json seeds; shell/variable-get-devdb.tsv holds the checks
# of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi variable get devdb
echo uefisettings-shell: step devdb %lasterror%
uefisettings.efi variable get devdb D719B2CB-3D3A-4596-A3BC-DAD00E67656F
echo uefisettings-shell: step image-security-vendor %lasterror%
uefisettings.efi variable get devdb 8C78A505-BAA0-4C4A-869F-000000000401
echo uefisettings-shell: step foreign-vendor %lasterror%
uefisettings.efi variable set devdb x
echo uefisettings-shell: step set-refused %lasterror%
uefisettings.efi variable get devdb
echo uefisettings-shell: step devdb-after-set %lasterror%
echo uefisettings-shell: done
reset -s
