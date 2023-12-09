# Applying Redundant State Detection Techniques to Angr

## Members:
Cuong Nguyen - cuongnd@seas.upenn.edu
Ye Tian - tyisme@seas.upenn.edu

## Organization:
- Our implementation for KLEE Random Path Selection Algorithm and Redundant State Detection Algorithm:
+ angr/angr/exploration_techniques/klee_rand_path_selection.py
+ angr/angr/exploration_techniques/redundant_state_detection.py




### Binary Analysis
Binary analysis is the process of examining and understanding the behavior and structure of binary code, which is the machine code that computers execute directly. In the context of computer science and cybersecurity, binary analysis is a crucial aspect of various tasks, including reverse engineering, vulnerability discovery, malware analysis, and program understanding. 

### Angr

Angr is a binary analysis framework designed to perform program analysis tasks on binary code. It is written in Python and provides a set of tools and libraries for analyzing and understanding the behavior of binary programs. Angr is particularly useful for tasks such as symbolic execution, concolic execution, and static analysis of binary code.

## Proposal

Angr uses its own simulator to simulate the states in the binary program. However, the way it explore the program is BFS by default. Therefore, we would apply the redundant state detection algorithm by implementing a new DFS-like exploration technique. The primary motivation behind this exploration technique is to enhance the efficiency of the angr framework by focusing on the uniqueness and relevance of states.

Our exploration technique, referred to as the Redundant State Detector, introduces a DFS-like approach to state exploration. It selectively defers exploration of alternative paths, aiming to prioritize and thoroughly investigate unique execution paths. The key components of the technique include:

* Path Deferral: The technique selectively defers alternative paths during exploration, allowing the analysis to concentrate on a single active path at a time.

* Path Similarity Calculation: The uniqueness of each path is determined by computing the average similarity between the active path and the deferred paths. Similarity is calculated based on a user-defined similarity function.

* Dynamic Dependency Graph: A dynamic dependency graph is maintained to capture dependencies between states. This graph aids in identifying relevant branches and updating the sets of relevant locations.

The technique introduces two stashes: relevant and deferred. The relevant stash holds the active path, while the deferred stash contains alternative paths that are deferred for exploration.

#### Uniqueness Evaluation
The uniqueness of a path is evaluated by comparing its execution with the other deferred paths. A user-defined similarity function, based on the L2 distance between the counts of state addresses in the path history, is employed by default.

#### Updating Dynamic Dependency Graph
A dynamic dependency graph is utilized to capture dependencies between states. The graph is updated during exploration to assist in identifying relevant branches and updating sets of relevant locations.

