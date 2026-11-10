echo -off
# The boot of the scenario shell-time-storage, on the MyIfrNVData of vars/my-ifr-nv-data.json:
# publish-hiidb.efi wakeup-time-forms arms the wake-up alarm for 23:59:59 of the day, creates
# DateTimeData and registers the forms of publish-hiidb/src/wakeup_time_forms.rs, which
# uefisettings.efi exports with DriverSample's; shell/time-storage.tsv holds the checks of the
# steps, and shell/time-storage.aarch64.tsv those on aarch64, whose PL031 has no wake-up alarm.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii get --json "Wake-up time"
echo uefisettings-shell: step get-wakeup-time %lasterror%
uefisettings.efi hii set --json "Wake-up time" 23:59:58
echo uefisettings-shell: step set-wakeup-time %lasterror%
uefisettings.efi hii get --json "Wake-up time"
echo uefisettings-shell: step get-wakeup-time-after %lasterror%
uefisettings.efi hii set --json "Wake-up date" 1899-12-31
echo uefisettings-shell: step set-wakeup-date-1899 %lasterror%
dmpstore DateTimeData -guid 8C78A505-BAA0-4C4A-869F-000000000501
echo uefisettings-shell: step dmpstore-before %lasterror%
uefisettings.efi hii get --json "Stored date"
echo uefisettings-shell: step get-stored-date %lasterror%
uefisettings.efi hii set --json "Stored date" 2025-03-01
echo uefisettings-shell: step set-stored-date %lasterror%
uefisettings.efi hii get --json "Stored time"
echo uefisettings-shell: step get-stored-time %lasterror%
uefisettings.efi hii set --json "Stored time" 23:01:--
echo uefisettings-shell: step set-stored-time %lasterror%
uefisettings.efi hii set --json "Stored time" 23:01:02
echo uefisettings-shell: step set-stored-second %lasterror%
dmpstore DateTimeData -guid 8C78A505-BAA0-4C4A-869F-000000000501
echo uefisettings-shell: step dmpstore-after %lasterror%
uefisettings.efi hii get --json --include suppressed "System Date"
echo uefisettings-shell: step get-system-date %lasterror%
uefisettings.efi hii set --json --include suppressed "System Date" 2030-06-15
echo uefisettings-shell: step set-system-date %lasterror%
uefisettings.efi hii get --json --include suppressed "System Date"
echo uefisettings-shell: step get-system-date-after %lasterror%
uefisettings.efi hii set --json --include suppressed "System Time" 10:20:30
echo uefisettings-shell: step set-system-time %lasterror%
dmpstore MyIfrNVData -guid A04A27F4-DF00-4D42-B552-39511302113D
echo uefisettings-shell: step dmpstore-my-ifr-nv-data %lasterror%
echo uefisettings-shell: done
reset -s
