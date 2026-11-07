echo -off
# The second boot of the scenarios shell-capsule-results and shell-capsule-results-i686:
# uefisettings.efi prints the results of capsule processing that the variables of
# vars/capsule-results-64.json or -32.json hold, which Linux printed the boot before, and the
# JSON capsule result table that publish-hiidb.efi json-capsule-result installs.
# shell/capsule-results.tsv holds the checks of its steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi capsule results
echo uefisettings-shell: step results %lasterror%
uefisettings.efi capsule result-table
echo uefisettings-shell: step result-table %lasterror%
echo uefisettings-shell: done
reset -s
