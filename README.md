# Lab assignments completed as part of Mathias Payer's Software Security course at EPFL (CS-412), summer term 2022.

## Lab 0x01: Code review

Find, describe/classify, and fix bugs in the YOLOpng C library.

## Lab 0x02: CTF

This part is a bit messy since there was no submission as such (rather, any retrieved flags were entered into the lab's system). Still, maybe I will find some of the pwn-scripts useful at some point in the future (we were using the *pwntools*-library for binary exploitation). Also I felt pretty savage cloning *Ghidra* - a tool for reverse engineering - from the NSA's GitHub account while completing this lab.

## Lab 0x03: Symbolic Execution

We were using the *angr*-Python-library for ehm essentially solving a bunch of constraints over given binaries. In general, symbolic execution is a technique for determining which inputs to a binary will produce a certain output - kind of finding a backwards path through the program from output to possible inputs. Unfortunately it doesn't scale, but it can complement fuzzing: given a POC (proof of concept, i.e. specific input that produces a certain bug) found using fuzzing, use symbolic execution to determine the *range* of inputs that produce this bug.

## Lab 0x04: Fuzzing

We were working with two different fuzzers for attacking the YOLOpng C library once more. *afl* (American Fuzzy Loop) was the first one; it uses genetic algorithms internally I think and hardly requires any work on the programmer's side (basically you just tell it: fuzz this program)! We love the simplicity, but it doesn't give us much flexibility - sometimes we want to fuzz a specific subsection of a program. This is where the second fuzzer *libfuzzer* comes in. With this one, you write stubs - little programs resembling unit tests that allow you to guide the fuzzer to a part of the program you're interested in.