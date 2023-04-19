# BUG-20
## Category
Arithmetic error/overflow

## Description
The `sqrt` operation will fail if `MAX_INT` is exceeded.

## Affected Lines in the original program
`circle.c:55`, `circle.c:65`, `circle.c:82`, `circle.c:92`

## Expected vs Observed


## Steps to Reproduce
E.g. for line 55: pass values for `radius` and `center_x` so that `radius * radius - (x - center_x) * (x - center_x))` is larger than `MAX_INT`.

### Command
````
./circle test_imgs/desert.png out.png 10 10 2147483647 ffffff
````

### Proof-of-Concept Input (if needed)
?

## Suggested Fix Description
Cast the value inside the call to `sqrt` to `long long`.