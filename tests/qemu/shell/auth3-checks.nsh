echo -off
# The Shell boot of the scenario shell-auth3-checks, on the secboot firmware in User Mode with
# run.sh's keys in \sign and a virtio-rng device, whose EFI_RNG_PROTOCOL seeds RSA blinding.
# vars/enhanced-auth-87.json seeds EnhancedAuthData, of TimeStamp 2026-11-06T12:00:00Z,
# EnhancedAuthRefused, whose metadata has Version 2, and EnhancedAuthNonce, whose current nonce is
# 8 bytes of 0xA5, each with the attributes 0x87. uefisettings.efi variable write-signed checks
# each write against the variable before it seeds or writes, and refuses what the firmware would
# refuse (UEFI 2.11 sections 8.2.3 and 8.2.5); the writes that it takes reach SetVariable(),
# which this firmware refuses for EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS. variable info
# shows the metadata of each. shell/auth3-checks.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
dmpstore EnhancedAuthData -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-before-data %lasterror%
dmpstore EnhancedAuthRefused -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-before-refused %lasterror%
dmpstore EnhancedAuthNonce -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-before-nonce %lasterror%
uefisettings.efi variable info EnhancedAuthNonce 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step info-nonce %lasterror%
uefisettings.efi variable info EnhancedAuthRefused 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step info-refused %lasterror%
uefisettings.efi variable write-signed EnhancedAuthData 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --timestamp 2026-11-06T12:00:00Z
echo uefisettings-shell: step ts-equal %lasterror%
uefisettings.efi variable write-signed EnhancedAuthData 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --timestamp 2026-11-06T11:59:59Z
echo uefisettings-shell: step ts-earlier %lasterror%
uefisettings.efi variable write-signed EnhancedAuthData 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --timestamp 2026-11-07T00:00:00Z
echo uefisettings-shell: step ts-later %lasterror%
uefisettings.efi variable write-signed EnhancedAuthData 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --timestamp 2026-11-07T00:00:00Z
echo uefisettings-shell: step other-attributes %lasterror%
uefisettings.efi variable write-signed EnhancedAuthData 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --nonce 0909090909
echo uefisettings-shell: step nonce-on-timestamp %lasterror%
uefisettings.efi variable write-signed EnhancedAuthRefused 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --timestamp 2026-11-07T00:00:00Z
echo uefisettings-shell: step refused-metadata %lasterror%
uefisettings.efi variable write-signed EnhancedAuthNonce 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --nonce a5a5a5a5a5a5a5a5
echo uefisettings-shell: step nonce-held %lasterror%
uefisettings.efi variable write-signed EnhancedAuthNonce 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --nonce 0909090909 --current-nonce 0101010101010101
echo uefisettings-shell: step nonce-other-current %lasterror%
uefisettings.efi variable write-signed EnhancedAuthNonce 8C78A505-BAA0-4C4A-869F-000000000301 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --nonce 0909090909
echo uefisettings-shell: step nonce-default %lasterror%
uefisettings.efi variable write-signed EnhancedProbe DE145B29-C3CD-455F-91DE-A76237B67C52 --attributes non-volatile,bootservice-access,runtime-access,enhanced-authenticated-access --data-file \sign\probe.data --signing-key-file \sign\KEK.key --signing-certificate-file \sign\KEK.crt --nonce 0909090909 --current-nonce 0101010101010101
echo uefisettings-shell: step current-nonce-create %lasterror%
dmpstore EnhancedAuthData -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-after-data %lasterror%
dmpstore EnhancedAuthRefused -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-after-refused %lasterror%
dmpstore EnhancedAuthNonce -guid 8C78A505-BAA0-4C4A-869F-000000000301
echo uefisettings-shell: step dmpstore-after-nonce %lasterror%
dmpstore EnhancedProbe -guid DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step dmpstore-probe %lasterror%
echo uefisettings-shell: done
reset -s
