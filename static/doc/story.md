

Generating the word list
-----

    wget http://d241g0t0c5miix.cloudfront.net/data/gutenberg_wordfreq.txt.gz
    gunzip -c gutenberg_wordfreq.txt.gz | cut -f 1 > gutenberg_2.txt
    cat gutenberg_2.txt | egrep '^[a-z]{3,8}$' > gutenberg_3.txt
    cat gutenberg_3.txt | tail -n +50 gutenberg_3.txt | head -65536 > gutenberg_4.txt

The file gutenberg_4.txt now contains 2<sup>16</sup> of the most common words in English.
We've excluded really short words, really long words, and the 50 most commom words like "and" and "the".
The words are all lowercase, no special characters. Each one can now encode two bytes of information.

