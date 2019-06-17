# set mixer to join channels to stereo output instead of mixing together
sed -i '' 's/define NUM_INPUTS 4/define NUM_INPUTS 2/' recording-daemon/mix.c
sed -i '' 's/no amix filter available/no amerge filter available/' recording-daemon/mix.c
sed -i '' 's/avfilter_get_by_name("amix");/avfilter_get_by_name("amerge");/' recording-daemon/mix.c
