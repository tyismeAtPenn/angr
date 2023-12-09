import random

from angr.exploration_techniques import ExplorationTechnique


class KLEERandPathSelection(ExplorationTechnique):
    def __init__(self, **kwargs):
        super(KLEERandPathSelection, self).__init__()
    
    @staticmethod
    def rank(s, reverse=False):
        k = -1 if reverse else 1
        return k * s.globals['weight']
        
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        print(simgr.active)

        if len(simgr.stashes[stash]) == 1:
            return simgr

        elif len(simgr.stashes[stash]) == 0:
            pass  

        elif len(simgr.stashes[stash]) > 1:
            for s in simgr.stashes[stash]:
                s.globals['weight'] = s.globals.get('weight', 1) / len(simgr.stashes[stash])
            pass  

        try: 
            simgr.move(from_stash=stash, to_stash='deferred')
            if max([s.globals['weight'] for s in simgr.stashes['deferred']]) < 0.1:
                for s in simgr.stashes['deferred']:
                    s.globals['weight'] *= 10
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
