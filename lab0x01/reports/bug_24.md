# BUG-24
## Category
String vulnerability

## Description
Usage of unsafe functions `strcat` and `strncat`.

## Affected Lines in the original program
`solid.c:123`, `solid.c:124`

## Expected vs Observed
The `command`-array (size: `512`) is firstly filled with the character `0`. Then, first `"stat -c %s "` is appended using `strcat`, and `output_name` (maximum size: 500) therafter using `strncat`. The buffer is thus filled completely, not leaving room for a null-terminator.

Even if the arithmetic was correct here (it may well be that I am not understanding the internals of `strcat` and `strncat` well enough), I would still list this as a bug because it is bad style to have the code depend on magic numbers like this. Imagine a developer wanted to change the constant `OUTPUT_NAME_SIZE` but forgot to change the size of the `command`-array: then we would get an overflow. It is recommended to avoid such error-prone scenarios and stick to the best practice outlined in the `man`-pages (see `Suggested Fix Description`).

## Steps to Reproduce
Call the program with a value for `output_name` of length exactly equal to `OUTPUT_NAME_SIZE`.

### Command
````
./solid giN85DSfxAuzbGW4pJbKnApzBQEB92400BCaDY4Ix6p93RcrR6a7leRb4SxDIMr66VeLSeBBOcr3evd4iTiLc3jV4Maucld3C5wN2A7tzp4Ay6KxS8Gw5MCc9uEVFcMzeQIVi5aKaL84vhKS7hIUziGZgmdSVH3tJsPbSUtZDas4LJvaNzmV1zM2v72yX0F2IWGTRDVhhLlEPO81ZYI3IiZ8wlFhUOucPqRRxVqSlNJRvKl6BfNOvan0vUpTkn7OIHFXSGzTGrPbcZxcXWjcGs3qcK9uePZoCsurH4XXirugQdSHVrXNIjJBBv0vqGKfk9nUIsLKJp5Jf4ZJK41m2RFjZwfpDG0CjUGaRcWwSSgWYhyKT2bPAfrPEGP9rn8dMOJf6Ksp2YMUZk7iQyuQY9auqHnGKWnsxuGEaqja2RU5hhZxvqa9BbTisPhHKtFAY26ZuaA1mAPAedyFOLCqKacvEv8k9deItW4TggiPcHXZEucs.png 50 50 ffffff
````

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Do not use `strcat`. Use `strncat` in the manner suggested by `man`, e.g. 
````
strncat(buf, argv[1], sizeof(buf) - sizeof(argv[1]) - 1);
buf[sizeof(buf) - 1] = '\0';
````