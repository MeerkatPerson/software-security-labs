
import angr
import networkx as nx
import sys

# load the binary
proj = angr.Project("./explore", load_options={"auto_load_libs": False})

# make a CFG
cfg = proj.analyses.CFGEmulated(normalize=True)

# this is the addr of the block containing the target (XREF)
addr = proj.loader.main_object.offset_to_addr(0x42C1)

# this is the addr of the instruction where 'CRASHING NOW' is printed
addr_ = proj.loader.main_object.offset_to_addr(0x42C5)

target = cfg.model.get_any_node(addr)
entry = list(cfg.graph.nodes())[0]

# entry = cfg.model.get_any_node(proj.entry)

# Find shortest path to target using the underlying networkx API
path = nx.shortest_path(cfg.graph, entry, target)

# Map the path to addresses to feed into tracer
path_addresses = list(map(lambda x: x.addr, path))

print(path)

state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

curr_addr_ind = 0

while True:

    simgr.explore(find=path_addresses[curr_addr_ind])

    curr_state = simgr.found[len(simgr.found)-1]

    if (curr_addr_ind == (len(path_addresses)-1)):

        crashing_input = curr_state.posix.dumps(sys.stdin.fileno())

        f = open("task_2.bin", "wb")

        f.write(crashing_input)

        f.close()

        # write to file as bytestream to .bin

        print(curr_state.posix.dumps(sys.stdin.fileno()))

        break

    else:

        curr_addr_ind += 1

        simgr = proj.factory.simulation_manager(curr_state)
