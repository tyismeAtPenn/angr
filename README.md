# Project Report: Applying Redundant State Detection Techniques to Angr

This project aims to enhance the angr binary analysis framework by incorporating redundant state detection techniques. Redundant state detection plays a crucial role in improving the efficiency and precision of symbolic execution engines. The project reimplements the redundant state detection algorithms and integrates them into the angr framework, to be more specific, exploration techniques, to optimize its performance on generating the inputs to increase the coverage.

## Introduction

### Binary Analysis
Binary analysis is the process of examining and understanding the behavior and structure of binary code, which is the machine code that computers execute directly. In the context of computer science and cybersecurity, binary analysis is a crucial aspect of various tasks, including reverse engineering, vulnerability discovery, malware analysis, and program understanding. 

### Angr

Angr is a binary analysis framework designed to perform program analysis tasks on binary code. It is written in Python and provides a set of tools and libraries for analyzing and understanding the behavior of binary programs. Angr is particularly useful for tasks such as symbolic execution, concolic execution, and static analysis of binary code.

## Proposal

### Architecture
Angr uses its own simulator to simulate the states in the binary program. However, the way it explore the program is BFS by default. Therefore, we would apply the redundant state detection algorithm by implementing a new DFS-like exploration technique. The primary motivation behind this exploration technique is to enhance the efficiency of the angr framework by focusing on the uniqueness and relevance of states.

Our exploration technique, referred to as the Redundant State Detector, introduces a DFS-like approach to state exploration. It selectively defers exploration of alternative paths, aiming to prioritize and thoroughly investigate unique execution paths. The key components of the technique include:

* Path Deferral: The technique selectively defers alternative paths during exploration, allowing the analysis to concentrate on a single active path at a time.

* Path Similarity Calculation: The uniqueness of each path is determined by computing the average similarity between the active path and the deferred paths. Similarity is calculated based on a user-defined similarity function.

* Dynamic Dependency Graph: A dynamic dependency graph is maintained to capture dependencies between states. This graph aids in identifying relevant branches and updating the sets of relevant locations.



### Algorithm

