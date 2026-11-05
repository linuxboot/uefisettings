echo -off
# The boot of the scenario shell-write-signed-setup, on the secboot firmware with a template
# copy of its variable store: Setup Mode. uefisettings.efi variable write-signed refuses to
# append to db, a Secure Boot policy variable, before any write, but not to append the same
# payload to another variable, which the firmware refuses, as the payload's signature covers
# db. shell/write-signed-setup.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore SetupMode -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step setup-mode %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --payload-file \auth\db-append.auth
echo uefisettings-shell: step policy %lasterror%
uefisettings.efi variable info db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
echo uefisettings-shell: step db-absent %lasterror%
uefisettings.efi variable write-signed WriteSignedProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access --append --payload-file \auth\db-append.auth
echo uefisettings-shell: step probe %lasterror%
uefisettings.efi variable info WriteSignedProbe DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step probe-absent %lasterror%
echo uefisettings-shell: done
reset -s
