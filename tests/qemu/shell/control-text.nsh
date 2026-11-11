echo -off
# The boot of the scenario shell-control-text: publish-hiidb.efi control-text-forms registers a
# form set whose CHECKBOXes have the prompts P07<U+010D>Q and P08<U+200D>Q, whose low byte is CR.
# shell/control-text.tsv holds the checks of the steps.
fs0:
echo uefisettings-shell: start
uefisettings.efi hii show-ifr
echo uefisettings-shell: step show-ifr %lasterror%
uefisettings.efi hii list-questions --json
echo uefisettings-shell: step list-questions %lasterror%
echo uefisettings-shell: done
reset -s
