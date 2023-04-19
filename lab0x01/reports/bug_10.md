# BUG-10
## Category
Stack buffer overflow

## Description
The constant `OUTPUT_NAME_SIZE` is set to a value of `500`. However, in `UNIX` (`POSIX`), `PATH_MAX`, i.e. the maximum path length is `255`. 

## Affected Lines in the original program
`solid.c:6`

## Expected vs Observed
Expected: program works as intended as the size of `output` does not exceed the specified boundaries. Observed: program crashes as `output` path length exceeds 255.

## Steps to Reproduce
Call the program with a value for `output_name` exceeding 255 characters.

### Command

499 characters:

```
./solid dcb3bba212eee2eca2da4e1d3dee54b1a3eded2cb5e5423aacecbeac13ccb5ca31ad44b1b243414d3b424e3a1cb122534e4a5ee42a1bbeee4413cac5b243abc4b2a44b4442e233ccaa4ecb442ba4545eaa24bdcbb1d45a51eb15ae3c432d5b35535c3ea5eb324eaa3d3a2ca4523d44b2a15eb33134b32ab4b524a5aae4bd5c2a1dd241423ec4becc3422e35ae3d53ea3eaa45ab53db3e3ebd51a5d24eba54c2a2342d2c5e53ad452c15b1111b1bd1c455bc11453ac155a34e1e152c22dccea2e4ebc4bc53e2e322aed1c33ce3da52dace532d4ba2acdcc125111ea34ae33b41abeaec31cbdec5ea53e15eeae2531e2515be1544ba45ecde.png 50 50 ffffff
```

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Set `OUTPUT_NAME_SIZE` to 255 to conform to the `POSIX` standard.