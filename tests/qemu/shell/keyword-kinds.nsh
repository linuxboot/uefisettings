echo -off
# The boot of the scenario shell-keyword-kinds: publish-hiidb.efi keyword-kinds-forms creates
# KindStore and registers the forms of publish-hiidb/src/keyword_kinds_forms.rs for a handle of
# the device path 0104140005a5788ca0ba4a4c869f000000001e027fff0400, whose x-UEFI-ns keywords
# KindDate, KindTime, KindList, KindRef, KindString and KindText uefisettings.efi sets through
# the Keyword Handler; shell/keyword-kinds.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindDate&VALUE=010407e8"
echo uefisettings-shell: step set-date %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-date %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindDate&VALUE=010407e9"
echo uefisettings-shell: step set-date-suppressed-year %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-date-suppressed-year %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindTime&VALUE=38000d"
echo uefisettings-shell: step set-time %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-time %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindTime&VALUE=382218"
echo uefisettings-shell: step set-time-hour-24 %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-time-hour-24 %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindList&VALUE=010203"
echo uefisettings-shell: step set-list %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-list %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindList&VALUE=010003"
echo uefisettings-shell: step set-list-after-empty %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-list-after-empty %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindList&VALUE=000101"
echo uefisettings-shell: step set-list-twice %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-list-twice %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindRef&VALUE=01010101010101010101010101010101010101010101"
echo uefisettings-shell: step set-ref %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-ref %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindDate&VALUE=1f0c07e8&NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindList&VALUE=000103"
echo uefisettings-shell: step set-date-and-list %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-date-and-list %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=0000000000420041"
echo uefisettings-shell: step set-string %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string %lasterror%
uefisettings.efi hii keyword get --namespace x-UEFI-ns "PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString"
echo uefisettings-shell: step get-string %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindText&VALUE=00000042000a0041"
echo uefisettings-shell: step set-text %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-text %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=0044004300420041"
echo uefisettings-shell: step set-string-too-long %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string-too-long %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=0000004200000041"
echo uefisettings-shell: step set-string-unwritten %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string-unwritten %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=000000000000e000"
echo uefisettings-shell: step set-string-private-use %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string-private-use %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=000000000000d800"
echo uefisettings-shell: step set-string-surrogate %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string-surrogate %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=00000042000a0041"
echo uefisettings-shell: step set-string-line-break %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string-line-break %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=00420041"
echo uefisettings-shell: step set-string-width %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string-width %lasterror%
uefisettings.efi hii keyword set "NAMESPACE=x-UEFI-ns&PATH=0104140005a5788ca0ba4a4c869f000000001e027fff0400&KEYWORD=KindString&VALUE=0000000000420041&READONLY"
echo uefisettings-shell: step set-string-read-only-resp %lasterror%
dmpstore KindStore -guid 8C78A505-BAA0-4C4A-869F-000000001E01
echo uefisettings-shell: step dmpstore-string-read-only-resp %lasterror%
echo uefisettings-shell: done
reset -s
