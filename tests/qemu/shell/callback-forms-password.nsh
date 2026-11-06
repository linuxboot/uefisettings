echo -off
# The boot of the scenario shell-callback-forms-password: publish-hiidb.efi
# callback-forms-password registers a form set whose Buffer store holds a PASSWORD question
# beside a setting, and a question without a VarStore whose driver's CHANGED overwrites that
# setting, and a form set whose PASSWORD question is in a disabled form;
# shell/callback-forms-password.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
dmpstore CallbackPassword -guid DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step store-before %lasterror%
uefisettings.efi hii get --json "Callback value beside a password"
echo uefisettings-shell: step get %lasterror%
uefisettings.efi hii get --json "Callback value beside a disabled password"
echo uefisettings-shell: step get-disabled %lasterror%
uefisettings.efi hii set --json "Callback value beside a password" On
echo uefisettings-shell: step set-refused %lasterror%
uefisettings.efi hii set --json --i-am-fine-to-brick-this-system "Callback value beside a password" On
echo uefisettings-shell: step set %lasterror%
dmpstore CallbackPassword -guid DE145B29-C3CD-455F-91DE-A76237B67C52
echo uefisettings-shell: step store-after %lasterror%
echo uefisettings-shell: done
reset -s
