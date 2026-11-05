echo -off
# The Shell boot of the scenario shell-write-signed-user, on the secboot firmware with per-run
# PK, KEK and db enrolled: uefisettings.efi variable write-signed appends to db the KEK-signed
# payload of the Shell boots, then its tampered copy and the same append signed with db's key
# and with a foreign key, then creates WriteSignedProbe, a variable of no policy, with a
# KEK-signed write without --append; the Linux boot write_signed/after_shell checks db's lists
# after it.
# shell/write-signed-user.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore SetupMode -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step setup-mode %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --payload-file \auth\db-append.auth
echo uefisettings-shell: step append %lasterror%
dmpstore db -guid D719B2CB-3D3A-4596-A3BC-DAD00E67656F
echo uefisettings-shell: step db-appended %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --payload-file \auth\db-tampered.auth
echo uefisettings-shell: step tampered %lasterror%
dmpstore db -guid D719B2CB-3D3A-4596-A3BC-DAD00E67656F
echo uefisettings-shell: step db-after-tampered %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --payload-file \auth\db-unauthorized.auth
echo uefisettings-shell: step unauthorized %lasterror%
dmpstore db -guid D719B2CB-3D3A-4596-A3BC-DAD00E67656F
echo uefisettings-shell: step db-after-unauthorized %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --payload-file \auth\db-foreign.auth
echo uefisettings-shell: step foreign %lasterror%
dmpstore db -guid D719B2CB-3D3A-4596-A3BC-DAD00E67656F
echo uefisettings-shell: step db-after-foreign %lasterror%
uefisettings.efi variable write-signed WriteSignedProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access --payload-file \auth\probe-write.auth
echo uefisettings-shell: step probe-write %lasterror%
uefisettings.efi variable info WriteSignedProbe DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step probe-info %lasterror%
echo uefisettings-shell: done
reset -s
