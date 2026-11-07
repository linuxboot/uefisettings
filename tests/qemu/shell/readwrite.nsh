echo -off
# The boot of the scenario shell-readwrite: DriverSample creates its variable MyIfrNVData, then
# publish-hiidb.efi rt-data-readwrite-forms creates ReadWriteData and registers the forms of
# publish-hiidb/src/readwrite_forms.rs, which uefisettings.efi exports with DriverSample's;
# shell/readwrite.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-serial-before %lasterror%
uefisettings.efi hii get --json "Serial port number"
echo uefisettings-shell: step get-serial-before %lasterror%
uefisettings.efi hii set --json "Serial port number" "Serial port 3"
echo uefisettings-shell: step set-serial %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-serial-after %lasterror%
uefisettings.efi hii get --json "Serial port number"
echo uefisettings-shell: step get-serial-after %lasterror%
dmpstore ReadWriteData -guid 8C78A505-BAA0-4C4A-869F-000000000201
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii get --json "Read transformed"
echo uefisettings-shell: step get-read-transformed-before %lasterror%
uefisettings.efi hii get --json "Mapped choice"
echo uefisettings-shell: step get-mapped-before %lasterror%
uefisettings.efi hii set --json "Mapped choice" Second
echo uefisettings-shell: step set-mapped %lasterror%
uefisettings.efi hii get --json "Mapped choice"
echo uefisettings-shell: step get-mapped-after %lasterror%
uefisettings.efi hii get --json "Read only"
echo uefisettings-shell: step get-read-only-before %lasterror%
uefisettings.efi hii get --json "Computed value"
echo uefisettings-shell: step get-computed-before %lasterror%
uefisettings.efi hii set --json "Linked value" 5
echo uefisettings-shell: step set-linked %lasterror%
uefisettings.efi hii get --json "Read only"
echo uefisettings-shell: step get-read-only-after %lasterror%
uefisettings.efi hii get --json "Computed value"
echo uefisettings-shell: step get-computed-after %lasterror%
uefisettings.efi hii set --json "Write only" 9
echo uefisettings-shell: step set-write-only %lasterror%
uefisettings.efi hii set --json "Read transformed" 100
echo uefisettings-shell: step set-read-transformed %lasterror%
uefisettings.efi hii get --json "Read transformed"
echo uefisettings-shell: step get-read-transformed-after %lasterror%
dmpstore ReadWriteData -guid 8C78A505-BAA0-4C4A-869F-000000000201
echo uefisettings-shell: step dmpstore-after %lasterror%
uefisettings.efi hii set --json "Absent target" 5
echo uefisettings-shell: step set-absent-target %lasterror%
uefisettings.efi hii set --json "Computed value" 7
echo uefisettings-shell: step set-computed %lasterror%
uefisettings.efi hii get --json "Driver held"
echo uefisettings-shell: step get-driver-held %lasterror%
uefisettings.efi hii set --json "Driver held" First
echo uefisettings-shell: step set-driver-held %lasterror%
uefisettings.efi hii get --json "No value source"
echo uefisettings-shell: step get-no-value-source %lasterror%
uefisettings.efi hii set --json "No value source" 1
echo uefisettings-shell: step set-no-value-source %lasterror%
uefisettings.efi hii get --json "Write only"
echo uefisettings-shell: step get-write-only %lasterror%
uefisettings.efi hii set --json "Read only" 1
echo uefisettings-shell: step set-read-only %lasterror%
uefisettings.efi hii get --json "Unevaluated read"
echo uefisettings-shell: step get-unevaluated-read %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
dmpstore ReadWriteData -guid 8C78A505-BAA0-4C4A-869F-000000000201
echo uefisettings-shell: step dmpstore-refused %lasterror%
dmpstore AbsentBuffer -guid 8C78A505-BAA0-4C4A-869F-000000000201
echo uefisettings-shell: step dmpstore-absent %lasterror%
echo uefisettings-shell: done
reset -s
