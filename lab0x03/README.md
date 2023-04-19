# Lab 0x03 - Symbolic Execution

This lab will represent a brief introduction into symbolic execution and constraint solving. The
first phase of the lab is released at http://hexhive004.iccluster.epfl.ch. If time permits, a second
phase will be released (at most by 25.04.2022) and you will be notified accordingly. Both phases
would share the same deadline and submission format.

Submission deadline: 02.05.2022 - 22:59:59 CET

## Grading

This lab is graded over 30 points, with each of the three tasks constituting 10 points. If a second
phase is released, the point distribution will again be uniform over the total number of tasks.

Refer to the last section of this handout for instructions on tasks and deliverables.

## What is it?

It is math, on steroids.

## No, really?

> "Symbolic execution is making sense of the world by playing a game of “what if?”"
> 
> "Symbolic execution is like a Sudoku puzzle for computer programs."
> 
> "What is symbolic execution? It's when you kill a person to save a hundred."

\- _GPT-3, circa 2022, transcribed_

Symbolic execution is the systematic exploration of a program's path space starting from its entry
point. Instead of executing each instruction of the program on _concrete_ data (e.g. bytes and
integers), instructions are modeled as state constraints, i.e. expressions that describe the side
effects of executing these instructions. For every instruction the symbolic executor encounters, it
adds its constraints to the current program state being explored. Exploration along a _path_
generally stops when the state of the program is determined to be terminating (i.e. a dead-end).

The nature of control flow on most machines is sequential: when an instruction executes, the next
instruction immediately following the current one is scheduled for execution. However, control-flow
transfers occur when a branch is encountered: conditional or unconditional.

When a unconditional branch is encountered (e.g. `jmp`, `call`, etc...), control-flow jumps to the
new location, and a symbolic executor merely follows it. In contrast, when a conditional branch is
processed, execution may follow one of two paths: a `true (taken)` one and a `false
(not-taken)` one. To make sure it covers all possible paths, the symbolic executor follows both
branch directions by forking the current program state, appending an additional constraint to each
of the children: the condition is `true` for the taken branch and `false` for the not-taken one. As
such, the number of paths in a program is exponential in the number of branches present (and the
same branches can be taken multiple times, e.g. in loops).

Each state maintained by the symbolic executor thus describes some path throughout the program, and
given enough resources (and assuming soundness and completeness of the engine), you should be able
to cover all paths throughout a program, with access to the state constraints at the end of each
path.

## Why is symbolic execution useful?

Because it gives you hope that, somehow, any problem is solvable. Have a CTF challenge you want to
solve without pulling your hair reversing it? Have a bug in your code and cannot reproduce it? Have
an annoying TA asking you to solve a set of contrived and completely unrealistic problems to gain a
few points on a course from your master's degree which will probably not affect your chances of
landing a job in the slightest as long as you pass it because the market is saturated anyway and
your generation is doomed because of ever-rising inflation rates, accelerated climate change,
global warfare, overpopulation, and other problems on your little Earth which is but a mere
rounding error in the cosmological timeline of our universe?

Symbolic execution is the answer! Just throw your problem at it and let it grind! You will need that
extra warmth of your laptop for the upcoming ice age!

## When should I use symbolic execution?

Only when someone asks. Otherwise, you avoid it religiously, because whether you're a believer or
not, you'll go to hell and back before realizing it will not work past 3 demo use-cases and does not
scale to most applications in the real world. But, give it a try anyway, you might still get a paper
or two out of it.

## Why are we learning about it?

Great question, I'm glad you asked.

## How do I ~~symbolic execution~~ ~~symbolically execute~~ ~~exbolically symecute~~ run `angr`?

Now we're talking! First, make sure you have a recent python interpreter installed, >=3.7. Then, in
a virtual environment (because you should always `venv`.), run:
```bash
pip install angr
```

Have your binary to be analyzed at hand. Then, in a python script or interpreter session, run:
```python
import angr

p = angr.Project('./mybin', auto_load_libs=False)
simgr = p.factory.simgr()
simgr.explore()
```

And you're good to go! Well, not so fast (not even slightly fast, because angr is slow AF). What are
we exploring for? If we leave it running as such, angr will try to explore _all_ paths in the
program, and even if it somehow manages to finish, we cannot yet immediately discern what path was
followed or what the result of each path was.

### States and the Simulation Manager

To entertain that thought, let's discuss the `SimulationManager` a bit. The way it was constructed
here (without arguments), it starts exploring at the program's entry state and maintains a _stash_
of **active** states being explored (in some order, e.g. round-robin or depth-first). To explore
the successors of each state, the simgr calls `state.step()`, which returns a list of successor
states. As discussed above, this is a list of one item in the case of unconditional branching, and
two items in the other case. The simgr appends successor states to the **active** stash, and
continues exploring states from that stash until it is empty. A state with no successors is
considered terminal and is moved to the **deadended** stash. These states are usually the result of
calls to `exit()`. There's a few more default stashes, and even more custom stashes for each
exploration technique used, and you can read about those in the
[angr API documentation](https://docs.angr.io/core-concepts/pathgroups#stash-types).

To get access to the entry state and explore it manually, you can run:
```python
state = p.factory.entry_state()
succ = state.step()
```

Each call to `state.step()` executes and collects constraints for an entire basic block starting at
that state's address, returning the successor states whose constraints are adjusted accordingly.
Bear in mind that the original state itself is not modified while stepping; new states are instead
created.

### The Loader

A state's address is given by `state.addr`, which represents the _rebased address_ of the program
counter. A rebased address is basically an address of an object in memory after the loader has
finished laying out the executable and other sections in the available address space. To obtain the
offset of a basic block relative to the beginning of the code section, run:
```python
offset = p.loader.main_object.addr_to_offset(addr)
```
where `addr` is the address of the basic block, as obtained from `state.addr` for instance.

Conversely, to obtain the rebased address:
```python
addr = p.loader.main_object.offset_to_addr(offset)
```

As you may have noticed, this is only in reference to the main object, which is always the
executable on which you are performing the analysis (as specified in the `angr.Project`
constructor). So a question follows: are there more objects? Well, in our case, the only loaded
executable is the main object, because we opted out of loading external libraries through
`auto_load_libs=False`. That doesn't mean there are no other objects though: the loader still
allocates virtual memory regions for other entities, such as syscall handlers, function summaries,
etc... To view the full list of objects, run:
```python
p.loader.all_objects
```

The loader also provides access to symbols and relocations, but those are better explained in the
[angr API documentation](https://docs.angr.io/core-concepts/loading).

### The Solver

angr's job is to correctly explore states and collect constraints, but, constraints are nothing but
mathematical expressions describing variables. The values of those variables are not known until
those constraints are _solved_. To do that, angr employs external solvers like z3, and provides
convenient access to solver instances initialized with the state's constraints through
`state.solver`.

Let's say we are inspecting some state and would like to know the value of a register at that point
in execution. The state gives us access to its registers through the `regs` interface:
```python
rax = state.regs.rax
```

The type of the returned variable is a bit vector, which is essentially an Abstract Syntax Tree
(AST) describing the expression to obtain this variable's value, as well as the size of the variable
in bits. To evaluate `rax` as a python native type, we can invoke the solver:
```python
raxv = state.solver.eval(rax)
```

This invokes the solver, providing it with the current state constraints and the expression we're
trying to evaluate. As such, it attempts to solve the constraints for the unresolved variables in
the expression then yields the final result of the calculation with known values. Unless the
constraints have only one solution, the obtained result is not unique. You can attempt to obtain
up to `N` solutions by calling the solver as follows:
```python
raxvs = state.solver.eval_upto(rax, n=N)
```
which returns a list of up to N solutions.

You can also find the minimum and maximum solutions with `solver.min(e)` and `solver.max(e)`, or
determine the satisfiability of the constraints with `solver.satisfiable()`.

The state solver `SimSolver` is a wrapper around the underlying solver module `claripy.Solver`,
which has a slightly different interface, and thus care must be taken when dealing with the two
types of solvers.

Read more about the solver in the [angr API documentation](https://docs.angr.io/core-concepts/solver).

### What is the solver doing?

His best :(

### Okay, so after this huge intro, how do I explore a target properly?

Well now that you're an expert in angr, time for some angr management (I'm not the first one to make
this joke, nor will I be the last).

Recall that the state loader allows you to `explore()` starting from some state. Well, the `explore`
method accepts some additional keyword arguments, of which `find` and `avoid` are of particular
interest. These can be a (rebased) address, a list of addresses, or a function that accepts a state
as argument and returns a boolean value.

Assuming we're interested in reaching some basic block whose address is 0x40abc, we can tell angr to
explore in all directions until it finds it:
```python
simgr = p.factory.simgr()
s.explore(find=0x40abc)
my_state = s.found[0]
```

This can still be inefficient, as angr still attempts to explore all paths and branches until such a
state is encountered. It is thus helpful to ask angr to avoid exploring certain states, to eliminate
entire paths from the exploration:
```python
simgr = p.factory.simgr()
s.explore(find=0x40abc, avoid=(0x40bcd, 0x40cde, 0x40def))
my_state = s.found[0]
```

Finally, assuming our state holds interesting data, we can inspect that data using our state
variable:
```python
# what did it output to stdout
stdout = my_state.posix.stdout.concretize()[0]
# what did it read from stdin
stdin  = my_state.posix.stdin.concretize()[0]
# what is the value of some memory address
memv = my_state.mem[0x1000].int.concrete
```

### Can I solve constraints without symbolic execution?

Yes, and for this lab, you kinda have to. As mentioned before, angr relies on a library called
claripy to provide access to solver engines, mainly z3.

While the interface to that solver is slightly different than angr's SimSolver, the idea is still
the same:
```python
import claripy

# assume you have some AST bitvectors x and y

s = claripy.Solver()
s.add(x == 10)
yv = s.eval(y, 1)[0]
```
Then `yv` stores one solution for `y` (if available) given the constraint `x == 10`.

To create those AST bitvectors `x` and `y`, one way would be:
```python
a = claripy.BVS('a', 32) # create a 32-bit symbolic variable named 'a'
b = claripy.BVS('b', 32)

c = a * b
d = a - b

x = claripy.RotateLeft(c + d, 8)
y = claripy.RotateRight(c - d, 16)
```

You could even pass `x` and `y` through functions that apply mathematical transformations (like the
ones used above) to generate new ASTs and use those to add constraints to the solver and find
solutions to the obtained system. This will come extra handy in the CRC32 challenge bellow.

### Oof, that's a lot. TL;DR?

angr make cpu go brrrrr

## The Assignment

To access the assignment, head on over to http://hexhive004.iccluster.epfl.ch. Fill in your @epfl.ch
e-mail address, and press Download.

You will receive a gzipped tar archive of some files relevant to the following tasks.

### Task 1: Solve a system of equations

You are given a file `equations.txt` containing a system of 5 equations in `x` and `y`, and you are
asked to provide a solution for that system.

Once found, save your solution in a `task_1.json` file with the following schema:
```json
{
	"x": your_x_value_as_int,
	"y": your_y_value_as_int
}
```

Also submit your Python code as a `task_1.py` file. Your python code should be able to generate the
`task_1.json` file and output it to the current working directory.

### Task 2: Find the path to a crash

You are provided with an x86_64 compiled binary `explore`, and you are asked to find an input
(over stdin) that crashes the target, outputting "CRASHING NOW!" to stdout. Use the skills you
learned in the CTF to reverse engineer the target, find the destination basic block, and, based on
the info provided above on angr (and your own research and vigilance), guide symbolic execution in
the direction of the block, and finally save the input stream that crashes the binary to
`task_2.bin`. Test that the generated input does in fact crash the binary with:
```bash
./explore < task_2.bin
```

_Hint: Check out angr's analyses if you want to make your life somewhat easier._

Do not forget to submit your `task_2.py` Python script which generates `task_2.bin`.

### Task 3: Calculate a CRC32 pre-image

In `preimage.txt`, you are given information about how a CRC32 checksum was calculated for some
flag. The flag length and charset are also provided. Your task is to find a string whose CRC32
value evaluates to that provided in the file. Save your flag in `task_3.txt` and provide the script
to generate it in `task_3.py`.

For this task, it will be of great help to check out this previous CTF write-up on solving a similar
challenge, but for CRC32-C:
https://ctftime.org/writeup/22420

## Deliverables

You are asked to provide an archive named `submission.tar.gz` which has the following structure:
```
.
|_ task_1.json
|_ task_1.py
|_ task_2.bin
|_ task_2.py
|_ task_3.txt
|_ task_3.py
```
Non-conforming submissions are subject to a penalty.

Upload your archive to moodle in the relevant submission dialog.