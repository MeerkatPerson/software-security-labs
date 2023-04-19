# BUG-1 
## Category
Temporal safety violation

## Description
After allocating memory for the `px` field of the `img` struct (line 89), in line 90 it is checked whether this allocation has been successful. If it wasn't, the memory allocated for the `img` struct is freed once in line 91, and a second time in line 145 after following the `goto` command to `error_img`. 
This corresponds to [CWE-415: Double Free](https://cwe.mitre.org/data/definitions/415.html), which potentially leads to a modification of unexpected memory locations.

## Affected Lines in the original program
In `checkerboard.c:91` and `checkerboard.c:145`

## Expected vs Observed
The expected functionality of the program will not be affected by this bug. However, the expected *properties* of the program, in particular memory safety, will be affected.

## Steps to Reproduce
We enter this condition if the `malloc` in line 89 fails. This can happen if it is attempted to allocate an excessive amount of memory. We can achieve this by picking the `width` and `height` parameters als large as possible, i.e. `USHRT_MAX - 1` (= maximum possible value to still pass the checks in lines 37 and 43).

### Command

```
./checkerboard checkerboard_test.png 65534 65534 2 000000 ffffff
```

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Remove one of the two calls to `free`.
