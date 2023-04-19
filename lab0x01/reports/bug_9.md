# BUG-9
## Category
String vulnerability

## Description
Unchecked use of 'strcpy': Size of `argv[1]` not checked

## Affected Lines in the original program
`solid.c:33`

## Expected vs Observed
Expected: file output is written to the specified location. Observed: program aborts with `buffer overflow`.

## Steps to Reproduce

Call the program with a value for `output` that exceeds 499 characters (`0`-termination).

### Command

```
./solid wpP1r9udLYy6CimcLANxH5ZRfU48Sd4fDLe96x0u2hlMTYmWPn4cgQnbxu84DoCY5EtrAUuXBNiqlGdybV8T8AXpc5aeN92i80eysyweGffuZLf8w9HBx7jeGVlb8uFjF9hCKL0cSFWEAQ0QcCZaYUt1d7HQu7oQsFFbroA9hXH1Gin6BdfQm6ghDmjaCOglvVUSSsPIfUYj3RO8MTk7PfNSiI8jKNJbWXQyirz39V6JR3ZmOwtD2sMGAuT9NCVvjLQajoXcERYleXFEP8GtdGF0bLAoXDUe5Ce5WRavX7ubZJsdYlMMNeoje9BLsyC6kJGIk5dY27Sb7DOpJAcJ9zszj4C4CFrA3rLNDykPGzzul8JbB11ZywjfccTHp82MhykU9wfXl3CXapHhEaaF2uKGFw4ciRgxaR8qLVQvm0LOoJJih8s0GZx2QfuscROY3SKXcVPrx1nhIR7Uaz67NEDTs68boEWtcIJ9sTDPax9tZOoSyH3w.c 50 50 ffffff
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Check that the size of `argv[1]` does not exceed `OUTPUT_NAME_SIZE - 1` (`goto error` if it does).