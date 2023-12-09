import random
from angr.exploration_techniques import ExplorationTechnique

class KLEERandPathSelection(ExplorationTechnique):
    def __init__(self, **kwargs):
        super(KLEERandPathSelection, self).__init__()

    @staticmethod
    def rank(s, reverse=False):
        # A static method to compute the rank of a state based on its weight
        k = -1 if reverse else 1
        return k * s.globals['weight']

    def step(self, simgr, stash='active', **kwargs):
        # Perform a single step of exploration for the symbolic execution engine
        
        # Execute the step and print the active states
        simgr = simgr.step(stash=stash, **kwargs)
        print(simgr.active)

        # Case 1: If there is only one active state, return the current state
        if len(simgr.stashes[stash]) == 1:
            return simgr

        # Case 2: If there are no active states, do nothing
        elif len(simgr.stashes[stash]) == 0:
            pass

        # Case 3: If there are multiple active states
        elif len(simgr.stashes[stash]) > 1:
            # Assign weights to each state based on the number of active states
            for s in simgr.stashes[stash]:
                s.globals['weight'] = s.globals.get('weight', 1) / len(simgr.stashes[stash])
            pass

        try:
            # Move states from the 'stash' to 'deferred' stash
            simgr.move(from_stash=stash, to_stash='deferred')
            
            # If the maximum weight in the 'deferred' stash is less than 0.1,
            # increase the weights of states in the 'deferred' stash
            if max([s.globals['weight'] for s in simgr.stashes['deferred']]) < 0.1:
                for s in simgr.stashes['deferred']:
                    s.globals['weight'] *= 10
            
            # Choose a state from the 'deferred' stash based on weights
            n = random.uniform(0, sum([s.globals['weight'] for s in simgr.stashes['deferred']]))
            for s in simgr.stashes['deferred']:
                if n < s.globals['weight']:
                    simgr.stashes['deferred'].remove(s)
                    simgr.stashes[stash] = [s]
                    break
                n = n - s.globals['weight']
        
        except ValueError:
            pass

        return simgr
