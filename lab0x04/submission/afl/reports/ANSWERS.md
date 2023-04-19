
# ANSWERS TO THE QUESTIONS THAT HAVE BEEN VEXING US ALL OUR LIVES

## Why did you have to change `is_png_chunk_valid`?

Because the fuzzer will mostly generate bogus invalid inputs (explore each path probabilistically), only rarely will the input be valid. Too many CPU cycles would be wasted on crc checks. If this function would return 1 for most inputs the program would abort and we wouldn't be able to explore interesting behaviour.

## Why afl-clang?

To add instrumentation at compile-time. With normal compilation, AFL would have no information about coverage, which it needs to run its genetic algorithm.

## How many crashes in total did AFL produce?

Within a few minutes: 10.5k crashes, 10 saved.

## Why are hangs considered bugs?

Can be used for DOS attacks.

## Which interface of `libpgnparser` remains untested by AFL?

`store_png`, because we don't call it in `size.c`.