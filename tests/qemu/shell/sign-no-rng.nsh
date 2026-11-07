echo -off
# The Shell boot of the scenario shell-sign-no-rng, on the secboot firmware with per-run PK, KEK
# and db enrolled and no virtio-rng device: it lists the handles of EFI_RNG_PROTOCOL, then
# uefisettings.efi variable write-signed signs a db append with KEK's key, which needs that
# protocol to seed RSA blinding. shell/sign-no-rng.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dh -p 3152BCA5-EADE-433D-862E-C01CDC291F44
echo uefisettings-shell: step rng-handles %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\sha256.esl --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt
echo uefisettings-shell: step sign %lasterror%
uefisettings.efi variable get db
echo uefisettings-shell: step db %lasterror%
echo uefisettings-shell: done
reset -s
