# BUG-11
## Category
Command injection

## Description
Calling `system` uses a command processor: cert-env33-c. An attacker can potentially execute code injected using the `output_name` parameter.

## Affected Lines in the original program
`solid.c:125`

## Expected vs Observed
Expected: use a system call to determine the size of the written output file. Observed: accidentially allow an attacker to execute code.

## Steps to Reproduce
Append a command to execute in terminal to the name of the output file as in the example command given below.

### Command

```
./solid "output.png ; ls" 50 50 ffffff
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Avoid call to system, use standard library functionality instead to determine size of file.