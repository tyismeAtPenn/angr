from difflib import SequenceMatcher
from collections import Counter

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
        self.defined_loc = {}               # dict from Symbols to defined loc
        self.relevant_symb_loc = {}         # dict from Symbols to branch loc
        self.test_input = []
        self.rel_loc_sets = set()
        
    def get_input(self):
        return self.test_input.copy()

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []
        if self.relevant_stash not in simgr.stashes:
            simgr.stashes[self.relevant_stash] = []

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if len(simgr.stashes[stash]) > 1:
            self._random.shuffle(simgr.stashes[stash])
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)

        if len(simgr.stashes[stash]) == 0:
            if len(simgr.stashes[self.deferred_stash]) == 0:
                return simgr
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())
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
        pass

    def FindMatch(self, state):
        pass

    def ConstructRelLocSets(self, state):
        # its implementation depends on how we define our graph
        pass

