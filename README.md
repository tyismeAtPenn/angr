# Applying Redundant State Detection Techniques to Angr

## Members:
Cuong Nguyen - cuongnd@seas.upenn.edu

Ye Tian - tyisme@seas.upenn.edu

## Organization:
### Implementation for KLEE Random Path Selection Algorithm and Redundant State Detection Algorithm:
- ```angr/angr/exploration_techniques/klee_rand_path_selection.py```
- ```angr/angr/exploration_techniques/redundant_state_detection.py```

### Evaluation analysis script:
- ```angr/klee_random_path_selection_analysis.py```

### Test programs:
- ```angr/crackme```

### Evaluation output:
- ```angr/analysis_output```

## How to run:
- Step 1: Clone this repo, ```cd angr`

- Step 2: ```python klee_random_path_selection_analysis.py```

- Step 3: ```python analysis_output/visualization.py```
