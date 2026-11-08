echo -off
# The Shell boot of the scenario shell-devdb-setup, on the secboot firmware with a template copy
# of its variable store, in Setup Mode, and a virtio-rng device, whose EFI_RNG_PROTOCOL seeds
# RSA blinding: uefisettings.efi variable write-signed refuses to append to devdb, a device
# signature database, signed with PK's key, before any write, then appends with
# --allow-setup-mode-write-without-signature-check, which creates it; the firmware then refuses
# an append signed with KEK's key and takes one signed with PK's. The Linux boot after it,
# write_signed/devdb_appended_by_the_shell, reads what this one wrote.
# shell/devdb-setup.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore SetupMode -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step setup-mode %lasterror%
uefisettings.efi variable get devdb
echo uefisettings-shell: step absent %lasterror%
uefisettings.efi variable write-signed devdb B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\devdb.esl --signing-key-file \sign\PK.key --signing-certificate-file \sign\PK.crt
echo uefisettings-shell: step refused %lasterror%
uefisettings.efi variable info devdb B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD
echo uefisettings-shell: step still-absent %lasterror%
uefisettings.efi variable write-signed devdb B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\devdb.esl --signing-key-file \sign\PK.key --signing-certificate-file \sign\PK.crt --allow-setup-mode-write-without-signature-check
echo uefisettings-shell: step written %lasterror%
uefisettings.efi variable get devdb
echo uefisettings-shell: step devdb %lasterror%
uefisettings.efi variable write-signed devdb B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\devdb2.esl --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --allow-setup-mode-write-without-signature-check
echo uefisettings-shell: step other-signer %lasterror%
uefisettings.efi variable get devdb
echo uefisettings-shell: step devdb-after-other-signer %lasterror%
uefisettings.efi variable write-signed devdb B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD --attributes non-volatile,bootservice-access,runtime-access --append --data-file \sign\devdb2.esl --signing-key-file \sign\PK.key --signing-certificate-file \sign\PK.crt --allow-setup-mode-write-without-signature-check
echo uefisettings-shell: step pk-append %lasterror%
uefisettings.efi variable get devdb
echo uefisettings-shell: step devdb-after-pk-append %lasterror%
echo uefisettings-shell: done
reset -s
