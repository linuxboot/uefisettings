echo -off
# The Shell boot of the scenario shell-sign-setup, on the secboot firmware with a template copy
# of its variable store, in Setup Mode, and a virtio-rng device, whose EFI_RNG_PROTOCOL seeds
# RSA blinding: uefisettings.efi variable write-signed refuses to write KEK, a Secure Boot
# policy variable, signed with PK's key, before any write, and with
# --allow-setup-mode-write-without-signature-check, which --i-am-fine-to-brick-this-system replaced,
# then writes it with --i-am-fine-to-brick-this-system, then PK, signed with its own key, which
# moves the firmware to User Mode. With SecureBoot then 1, the firmware would refuse to load
# uefisettings.efi, so the dmpstore of the Shell checks that last.
# shell/sign-setup.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore SetupMode -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step setup-mode %lasterror%
uefisettings.efi variable write-signed KEK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\KEK.esl --signing-key-file \sign\PK.key --signing-certificate-file \sign\PK.crt --timestamp 2026-01-01T00:00:00Z
echo uefisettings-shell: step kek-refused %lasterror%
uefisettings.efi variable info KEK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step kek-absent %lasterror%
uefisettings.efi variable write-signed KEK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\KEK.esl --signing-key-file \sign\PK.key --signing-certificate-file \sign\PK.crt --timestamp 2026-01-01T00:00:00Z --allow-setup-mode-write-without-signature-check
echo uefisettings-shell: step kek-removed-flag %lasterror%
uefisettings.efi variable write-signed KEK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\KEK.esl --signing-key-file \sign\PK.key --signing-certificate-file \sign\PK.crt --timestamp 2026-01-01T00:00:00Z --i-am-fine-to-brick-this-system
echo uefisettings-shell: step kek-written %lasterror%
uefisettings.efi variable get KEK
echo uefisettings-shell: step kek %lasterror%
uefisettings.efi variable write-signed PK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C --attributes non-volatile,bootservice-access,runtime-access --data-file \sign\PK.esl --signing-key-file \sign\PK.key --signing-certificate-file \sign\PK.crt --timestamp 2026-01-01T00:00:00Z --i-am-fine-to-brick-this-system
echo uefisettings-shell: step pk-written %lasterror%
dmpstore SetupMode -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step setup-mode-after %lasterror%
dmpstore SecureBoot -guid 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
echo uefisettings-shell: step secure-boot-after %lasterror%
echo uefisettings-shell: done
reset -s
