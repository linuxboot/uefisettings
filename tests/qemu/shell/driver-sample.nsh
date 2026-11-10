echo -off
# The first boot of the scenario shell-driver-sample; run.sh copies this file to the ESP as
# startup.nsh, and shell/driver-sample.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Activate this check box"
echo uefisettings-shell: step get-check-box %lasterror%
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get-numeric %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 42
echo uefisettings-shell: step set-numeric %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-after %lasterror%
uefisettings.efi hii get --json "How old are you? (Step)"
echo uefisettings-shell: step get-numeric-after %lasterror%
uefisettings.efi hii get --json "How tall are you? (Hex)"
echo uefisettings-shell: step get-efi-var %lasterror%
uefisettings.efi hii set --json "How tall are you? (Hex)" 20
echo uefisettings-shell: step set-efi-var %lasterror%
uefisettings.efi hii get --json "How tall are you? (Hex)"
echo uefisettings-shell: step get-efi-var-after %lasterror%
dmpstore MyEfiVar -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-efi-var %lasterror%
uefisettings.efi hii get --json "No such question anywhere"
echo uefisettings-shell: step get-unknown %lasterror%
uefisettings.efi hii set --json "No such question anywhere" 1
echo uefisettings-shell: step set-unknown %lasterror%
uefisettings.efi hii set --json "How old are you? (Step)" 250
echo uefisettings-shell: step set-out-of-range %lasterror%
uefisettings.efi bogus-subcommand
echo uefisettings-shell: step usage-error %lasterror%
uefisettings.efi hii set "How old are you? (Step)"
echo uefisettings-shell: step missing-value %lasterror%
uefisettings.efi hii extract-db hiidb.bin
echo uefisettings-shell: step extract-db %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-negatives %lasterror%
uefisettings.efi hii get --json "String - Interactive"
echo uefisettings-shell: step get-string %lasterror%
uefisettings.efi hii set --json "String - Interactive" STRING
echo uefisettings-shell: step set-string %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-string %lasterror%
uefisettings.efi hii set --json "String - Interactive" abc
echo uefisettings-shell: step set-string-short %lasterror%
uefisettings.efi hii set --json "String - Interactive" SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
echo uefisettings-shell: step set-string-long %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-string-negatives %lasterror%
uefisettings.efi hii get --json "Activate this check box" >v captured
echo uefisettings-shell: step capture %lasterror%
set
echo uefisettings-shell: step variables %lasterror%
uefisettings.efi get --json "Activate this check box"
echo uefisettings-shell: step top-get %lasterror%
uefisettings.efi set --json "Activate this check box" 0
echo uefisettings-shell: step top-set %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
uefisettings.efi hii list-strings --json
echo uefisettings-shell: step list-strings %lasterror%
uefisettings.efi show-translations --json
echo uefisettings-shell: step show-translations %lasterror%
uefisettings.efi hii get --json --no-efivars "Activate this check box"
echo uefisettings-shell: step no-efivars %lasterror%
uefisettings.efi variable list
echo uefisettings-shell: step variable-list %lasterror%
uefisettings.efi variable list --guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step variable-list-guid %lasterror%
uefisettings.efi variable list --guid A04A27F4
echo uefisettings-shell: step variable-list-bad-guid %lasterror%
uefisettings.efi variable info MyIfrNVData A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step variable-info %lasterror%
uefisettings.efi variable storage
echo uefisettings-shell: step variable-storage %lasterror%
uefisettings.efi variable storage --attributes non-volatile,bootservice-access
echo uefisettings-shell: step variable-storage-nv-bs %lasterror%
uefisettings.efi variable storage --attributes runtime-access
echo uefisettings-shell: step variable-storage-rt %lasterror%
uefisettings.efi --help
echo uefisettings-shell: step help %lasterror%
uefisettings.efi hii --help
echo uefisettings-shell: step hii-help %lasterror%
uefisettings.efi hii get --help
echo uefisettings-shell: step hii-get-help %lasterror%
uefisettings.efi hii set --help
echo uefisettings-shell: step hii-set-help %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable"
echo uefisettings-shell: step keyword-get %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns KEYWORD=iSCSIBootEnable
echo uefisettings-shell: step keyword-get-no-path %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&ReadWrite&Numeric:1"
echo uefisettings-shell: step keyword-filter %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&ReadOnly"
echo uefisettings-shell: step keyword-filter-none %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&Buffer"
echo uefisettings-shell: step keyword-filter-buffer %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&Numeric:3"
echo uefisettings-shell: step keyword-filter-bogus %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&KEYWORDINFO=DataType&ReadWrite&Numeric:1"
echo uefisettings-shell: step keyword-filter-info %lasterror%
uefisettings.efi hii keyword get --filter-by-get-data --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&ReadWrite&Numeric:1"
echo uefisettings-shell: step keyword-filter-get-data %lasterror%
uefisettings.efi hii keyword get --filter-by-get-data --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&Boolean"
echo uefisettings-shell: step keyword-filter-get-data-boolean %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&KEYWORD=xUefiHiiOption"
echo uefisettings-shell: step keyword-multi %lasterror%
uefisettings.efi hii keyword get --json --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&KEYWORD=xUefiHiiOption"
echo uefisettings-shell: step keyword-multi-json %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&KEYWORD=NoSuchKeyword"
echo uefisettings-shell: step keyword-multi-refused %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "KEYWORD=iSCSIBootEnable&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable"
echo uefisettings-shell: step keyword-multi-twice %lasterror%
uefisettings.efi hii keyword get --filter-by-get-data --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=xUefiHiiOption&ReadOnly"
echo uefisettings-shell: step keyword-multi-partial %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step keyword-dmpstore-before %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&VALUE=02"
echo uefisettings-shell: step keyword-set-no-option %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step keyword-dmpstore-refused %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&VALUE=03&NAMESPACE=x-UEFI-ns&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=xUefiHiiOption&VALUE=02"
echo uefisettings-shell: step keyword-set-second-no-option %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step keyword-dmpstore-second-refused %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&KEYWORDINFO=All"
echo uefisettings-shell: step keyword-info-get %lasterror%
uefisettings.efi hii keyword get --json --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&KEYWORDINFO=All"
echo uefisettings-shell: step keyword-info-json %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&KEYWORDINFO=Bogus"
echo uefisettings-shell: step keyword-info-bogus %lasterror%
uefisettings.efi hii keyword get --keyword-info-from-get-data --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&KEYWORDINFO=All"
echo uefisettings-shell: step keyword-info-get-data %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&VALUE=03"
echo uefisettings-shell: step keyword-set %lasterror%
uefisettings.efi hii keyword get --json --namespace x-UEFI-ns "PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable"
echo uefisettings-shell: step keyword-get-after %lasterror%
uefisettings.efi hii get --json "My Keyword Namespace Test"
echo uefisettings-shell: step keyword-question-after %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step keyword-dmpstore-after %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&VALUE=01&NAMESPACE=x-UEFI-ns&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&VALUE=03"
echo uefisettings-shell: step keyword-set-twice %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step keyword-dmpstore-twice-refused %lasterror%
uefisettings.efi hii keyword set --allow-volatile "NAMESPACE=x-UEFI-ns&PATH=01041400f4274aa000df424db55239511302113d7fff0400&KEYWORD=iSCSIBootEnable&VALUE=01"
echo uefisettings-shell: step keyword-set-allow-volatile %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step keyword-dmpstore-allow-volatile %lasterror%
uefisettings.efi hii keyword get --help
echo uefisettings-shell: step keyword-get-help %lasterror%
uefisettings.efi hii keyword set --help
echo uefisettings-shell: step keyword-set-help %lasterror%
echo uefisettings-shell: done
reset -s
