# BUG-17
## Category
Unchecked system call returning code

## Description
When calling a function from somewhere else, usually a library, we must perform a check to determine if that call was successful ([CWE-252](https://cwe.mitre.org/data/definitions/252.html)).

## Affected Lines in the original program
Calls to `malloc`, `load_png`, `store_png` are not checked in various locations:

- `checkerboard.c`: call to `store_png` not checked in line 129
- `circle.c`: call to `store_png` not checked in line 97
- `filter.c`: call to `store_png` not checked in line 287
- `rect.c`: call to `store_png` not checked in line 85
- `resize.c`: call to `store_png` not checked in line 75
- `solid.c`: call to `malloc` not checked in line 10
- `solid.c`: call to `system` not checked

## Expected vs Observed
According to the common weakness extended description: *'Two common programmer assumptions are "this function call can never fail" and "it doesn't matter if this function call fails". If an attacker can force the function to fail or otherwise return a value that is not expected, then the subsequent program logic could lead to a vulnerability, because the software is not in a state that the programmer assumes. For example, if the program calls a function to drop privileges but does not check the return code to ensure that privileges were successfully dropped, then the program will continue to operate with the higher privileges.'*

## Steps to Reproduce
Cause one of the calls to fail. 

### Command
````
./resize input.png rvCxTx7JeJG8bGc0LqOmbZ1owiddWReFQ4nWQ2eIBECmLitPnkD8hWEQuioCM8QCeU33XoHyeVNsJ6RyaCzEmSMdwRe7onhMkDv4SxKFpgaps4PLIvPaCy6GTEzXWiabDwZvX9c02uUDPCJBNmUFhKk9bwBsdv9kVj0GNLqKqTQmDJwqi8rRhywWUSSelS1QTmvyKRrqwjZ3g1L23wDniGf7Dq9iyhqa7HCpkllkipZxKs5k6Q9rTsYGXPu3v2Alw0W0ZLOsEI2052AMvFx701SsZnlK1748NZqTgFbXtsdr.png 1
````

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Check every call to a library function as in the example below:
````
struct pixel(*new_data)[img->size_x] =
      malloc(sizeof(struct pixel) * img->size_x * img->size_y);

  if (!new_data) {
    return;
  }
````