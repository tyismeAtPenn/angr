from difflib import SequenceMatcher
from collections import Counter

from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.sim_state import SimState
from angr.state_plugins.solver import SimSolver

from . import ExplorationTechnique


class RedundantStateDetector(ExplorationTechnique):
    """
    Redundant State Detector.

    Will only keep one path active at a time, any others will be deferred.
    The state that is explored depends on how unique it is relative to the other deferred states.
    A path's uniqueness is determined by its average similarity between the other (deferred) paths.
    Similarity is calculated based on the supplied `similarity_func`, which by default is:
    The (L2) distance between the counts of the state addresses in the history of the path.
    """

    def __init__(self, relevant_stash="relevant", deferred_stash="deferred"):
        """
        :param input: A byte array that specify the input.
        :param deferred_stash:  TBD.
        """
        super().__init__()
        # TODO: bind the input onto the state
        # state1.posix.stdin.store or sth
        self.relevant_stash = relevant_stash
        self.deferred_stash = deferred_stash
        self.defined_loc = {}               # dict from Symbols to defined loc addr
        self.relevant_symb_loc = {}         # dict from Symbols to branch loc addr
        self.relevant_branch_loc = {}
        self.test_input = []
        self.rel_loc_sets = {}              # dict from addr to symbols
        self.visited = set()                # set of visited addr
        self.graph = DepGraph()
        
    def get_input(self):
        return self.test_input.copy()

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []
        if self.relevant_stash not in simgr.stashes:
            simgr.stashes[self.relevant_stash] = []
        self.last_state = simgr.stashes["active"][0]

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if len(simgr.stashes[stash]) > 1:
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)
            return simgr

        # if reaches an deadend
        if len(simgr.stashes[stash]) == 0:
            # we shall compute for the input for that
            input_data = self.last_state.posix.stdin.load(0, self.last_state.posix.stdin.size)
            self.last_state.solver.eval(input_data)
            self.test_input.append(input_data)
            if len(simgr.stashes[self.deferred_stash]) == 0:      
                return simgr
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())

        # now only has one stash
        curr_state: SimState = simgr.stashes[stash][0]
        
        # first update the datadependency graph:
        self.UpdateDynamicDepGraph(curr_state)
        if curr_state.addr not in self.visited:
            # mark the code visited:
            self.visited.add(curr_state)
            self.UpdateRelBranchSet(curr_state)
            self.RefineRelLocSets(curr_state)
        
        # deadend would make stash has 0 elements, we don't need to handle that
        if self.find_match(curr_state):
            self.ConstructRelLocSets(curr_state)
            input_data = curr_state.posix.stdin.load(0, curr_state.posix.stdin.size)
            curr_state.solver.eval(input_data)
            self.test_input.append(input_data)
            simgr.stashes[stash].clear()
            return simgr

        return simgr
    
    @staticmethod
    def is_branch(self,state) -> bool:
        # TODO: find a way to decide whether it is on a branch
        curr_inst = state.solver.eval(state.regs.pc)
        if curr_inst.mnemonic.startswith("cmp"):
            return True
        return False
    
    def UpdateRelBranchSet(self, state):
        if self.is_branch(state):
            # TODO: if it only has one successor with another one uncovered
            # simgr.stashes[self.relevant_stash].append(state)
            # for symb : symbs:
            #   self.relevantSymb_loc[symb]=state
            pass

    def RefineRelLocSets(self, state):
        # TODO: if it defines var add it to define_loc
        #       if it kills it del/modify it from define_loc
        curr_inst = state.solver.eval(state.regs.pc)

    def UpdateDynamicDepGraph(self, state):
        # a graph that stores all states dependency
        if state.addr not in self.visited:
            self.graph.add_node(state.addr)
            self.graph.add_edge(self.last_state.addr,state.addr)

    def find_match(self, state: SimState)->bool:
        # compare the current with rel_loc_sets' constraints
        prev_constraints = self.rel_loc_sets[state.addr]
        # TODO: get constraints only about the symbols
        curr_constraints = None
        dummy_solver = SimSolver()
        prev_c = False
        for c in prev_constraints:
            prev_c = prev_c or not c
        dummy_solver.add(prev_c)        
        dummy_solver.add(curr_constraints)
        return not dummy_solver.satisfiable()
        

    def ConstructRelLocSets(self, state):
        # TODO: unfinished, should it be constructed only once
        # we have reached the end update the RelLocSets
        for symbol, states in self.relevant_symb_loc.items():
            if symbol in self.relevant_branch_loc:                
                path = self.graph.find_path(self.defined_loc[state],self.relevant_symb_loc[state])
                for node in path:
                    # TODO: refine relLocSets where doesn't have a value
                    if node not in self.rel_loc_sets:
                        pass
