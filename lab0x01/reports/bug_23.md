# BUG-23
## Category
Miscellanous

## Description
Hex color codes cannot be negative. However, the program does not prevent us from passing negative values for the hex colors. If such negative values are provided as input to the program, weird output is the result.

## Affected Lines in the original program
In `checkerboard.c:49` and `checkerboard.c:55`

## Expected vs Observed
Expected: when providing negative color codes (= invalid input), we expect the program to abort and provide information about what valid inputs should look like. Observed: the program just produces strange results.

## Steps to Reproduce
Call the program, providing 5-digit color codes that are negative.

### Command

```
./checkerboard checkerboard_test.png 100 100 10 -67894 -45678
```

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Add an additional check to ensure the passed color codes aren't negative.