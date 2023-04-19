# BUG-18
## Category
String vulnerability

## Description
Format string is not a string literal (potentially insecure): `printf(input)`

## Affected Lines in the original program
`filter.c:230`

## Expected vs Observed
Expected: if the name of an inexistent input file is provided to filter, the program crashes safely. Observed: an attacker can pass a malicious string as the name of the input file.

## Steps to Reproduce
Consider the example command given below: the `%s` specifier causes the function to read from an invalid address, while the `%n` specifier causes it to write to an invalid address.

### Command
````
./filter "A %s bad %n string" output.png negative
````

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Change to `printf("%s", input);`