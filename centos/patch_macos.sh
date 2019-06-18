# set mixer to join channels to stereo output instead of mixing together
gsed -i 's/define NUM_INPUTS 4/define NUM_INPUTS 2/' recording-daemon/mix.c
gsed -i 's/no amix filter available/no amerge filter available/' recording-daemon/mix.c
gsed -i 's/avfilter_get_by_name("amix");/avfilter_get_by_name("amerge");/' recording-daemon/mix.c
# set recording daemon wav file output for 2 channels, 16-bits
gsed -i '/stereo mixing goes here.*/a \\tout_format.channels = 2;\n\tout_format.format = AV_SAMPLE_FMT_S16;'  recording-daemon/decoder.c
