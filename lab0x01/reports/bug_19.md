# BUG-19
## Category
Stack buffer overflow

## Description
Use of unsafe function `strncpy` in `filter.c` without checking if the size of the to-be-copied input arguments exceed `ARG_SIZE`.

If an argument is provided to the filter, `strcpy` is used (even worse!).

## Affected Lines in the original program
`filter.c:219`, `filter.c:220`, `filter.c:221`, `filter.c:225`

## Expected vs Observed
Quoting from [a post on Stackoverflow](https://stackoverflow.com/questions/25746400/why-is-strncpy-marked-as-unsafe), `strncpy` has a few dangerous quirks:
- first, it zeros the target buffer past the end of the copy, which can be surprising.
- second, if there is not enough room in the target buffer, it does **not** null-terminate the target buffer.
- third, if it truncates, it 'mostly works'. Which discourages error handling (truncated strings are often worse than useless, but do not **appear** to be worse than useless at first glance).

As for `strcpy`, it should be avoided altogether as it does not impose any restrictions on the number of characters to be copied.

## Steps to Reproduce
Call the program with inputs exceeding `ARG_SIZE`, such as in the example command below.

### Command
./filter test_imgs/summer.png Jzrd7MJm4XIXDaeVBxjFMwoLId9NVIPfw4eBGiLuKseiLIwd2pMlAR6zMutoYIvHs7OhF8yDnmmp6c7CFy8xaTZG9ZGQA5ZVMNa2UZzjvzN9qoHmr2WuBOAZI2g46V2ss2cfrV9GKqOUJsvEhCdUGVBEKklMmnIyLZ4Asc70SqUscKJrikeySjEeg1uUcVOwb4XqYBzVQexJwKDaS3d9Tc7XxDG8I17yXkn1ddgUirguVXRv4c2TBlw0JNbotgj.png negative

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Check that the input arguments do not exceed `ARG_SIZE` before calling `strncpy`.