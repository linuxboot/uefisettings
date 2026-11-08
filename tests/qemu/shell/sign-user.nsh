echo -off
# The Shell boot of the scenario shell-sign-user, on the secboot firmware with per-run PK, KEK
# and db enrolled and a virtio-rng device, whose EFI_RNG_PROTOCOL seeds RSA blinding:
# uefisettings.efi variable write-signed signs with the keys that run.sh put in \sign. It appends
# to db with KEK's key over SHA-256, SHA-384 and SHA-512, and with the leaf key, whose bundle
# carries the CA that KEK issued; the firmware refuses the appends that db's key, the foreign key
# and the leaf key without its CA sign. It refuses a write without --append or --timestamp, as
# it reads no clock, then creates PrivateProbe, a private authenticated variable, with the
# foreign key, after which the firmware takes a later write by that key only. The firmware
# refuses EnhancedProbe's writes with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS: run.sh's
# pre-signed one in \auth, and those that uefisettings signs at a TimeStamp, with a nonce and
# with a NewCert.
# shell/sign-user.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dh -p 3152BCA5-EADE-433D-862E-C01CDC291F44
echo uefisettings-shell: step rng-handles %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\sha256.esl --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt
echo uefisettings-shell: step sha256 %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\sha384.esl --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --digest sha384
echo uefisettings-shell: step sha384 %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\sha512.esl --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --digest sha512
echo uefisettings-shell: step sha512 %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\chain.esl --signing-key-file \sign\leaf.key --signing-certificate-file \sign\chain.pem
echo uefisettings-shell: step chain %lasterror%
uefisettings.efi variable get db
echo uefisettings-shell: step db %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\refused.esl --signing-key-file \sign\db.key --signing-certificate-file \sign\db.crt
echo uefisettings-shell: step unauthorized %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\refused.esl --signing-key-file \sign\foreign.key --signing-certificate-file \sign\foreign.crt
echo uefisettings-shell: step foreign %lasterror%
uefisettings.efi variable write-signed db D719B2CB-3D3A-4596-A3BC-DAD00E67656F --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\refused.esl --signing-key-file \sign\leaf.key --signing-certificate-file \sign\leaf.crt
echo uefisettings-shell: step no-ca %lasterror%
uefisettings.efi variable get db
echo uefisettings-shell: step db-after-refused %lasterror%
uefisettings.efi variable write-signed PrivateProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\probe.data --signing-key-file \sign\foreign.key --signing-certificate-file \sign\foreign.crt
echo uefisettings-shell: step no-timestamp %lasterror%
uefisettings.efi variable write-signed PrivateProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\probe.data --signing-key-file \sign\foreign.key --signing-certificate-file \sign\foreign.crt --timestamp 2026-01-01T00:00:00Z
echo uefisettings-shell: step private-create %lasterror%
uefisettings.efi variable info PrivateProbe DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step private-info %lasterror%
uefisettings.efi variable write-signed PrivateProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\update.data --signing-key-file \sign\foreign.key --signing-certificate-file \sign\foreign.crt --timestamp 2026-01-02T00:00:00Z
echo uefisettings-shell: step private-update %lasterror%
uefisettings.efi variable write-signed PrivateProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\probe.data --signing-key-file \sign\foreign.key --signing-certificate-file \sign\foreign.crt --timestamp 2026-01-02T00:00:00Z
echo uefisettings-shell: step private-stale %lasterror%
uefisettings.efi variable write-signed PrivateProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\probe.data --signing-key-file \sign\db.key --signing-certificate-file \sign\db.crt --timestamp 2026-01-03T00:00:00Z
echo uefisettings-shell: step private-other-key %lasterror%
uefisettings.efi variable info PrivateProbe DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step private-info-after %lasterror%
uefisettings.efi variable write-signed EnhancedProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --payload-file \auth\enhanced.auth
echo uefisettings-shell: step enhanced-payload %lasterror%
uefisettings.efi variable write-signed EnhancedProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --timestamp 2026-01-01T00:00:00Z
echo uefisettings-shell: step enhanced-timestamp %lasterror%
uefisettings.efi variable write-signed EnhancedProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --nonce 0123456789abcdef
echo uefisettings-shell: step enhanced-nonce %lasterror%
uefisettings.efi variable write-signed EnhancedProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --nonce 0123456789abcdef --new-signing-key-file \sign\db.key --new-signing-certificate-file \sign\db.crt
echo uefisettings-shell: step enhanced-new-cert %lasterror%
dmpstore EnhancedProbe -guid DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step enhanced-dmpstore %lasterror%
echo uefisettings-shell: done
reset -s
