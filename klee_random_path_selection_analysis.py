import angr
import time
import os
import csv

directory_path = './crackme'
output_file_path = './analysis_output/analysis_output.csv'

# Get all file names in the directory
file_names = sorted([os.path.join(directory_path, f) for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))])
technique_DFS = angr.exploration_techniques.DFS()
technique_KLEE = angr.exploration_techniques.KLEERandPathSelection()

# Lists to store execution times and final states for each technique
results = []

with open(output_file_path, 'w', newline='') as csvfile:
    fieldnames = ['File', 'Technique', 'ExecutionTime', 'FinalState']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()

    for name in file_names:
        proj = angr.Project(name, auto_load_libs=False)
        state = proj.factory.entry_state()

        # BFS
        simgr = proj.factory.simulation_manager(state)
        start_time = time.time()
        simgr.run()
        end_time = time.time()
        execution_time_BFS = end_time - start_time
        final_states_BFS = simgr.stashes
        results.append({'File': name, 'Technique': 'BFS', 'ExecutionTime': execution_time_BFS, 'FinalState': final_states_BFS})
        writer.writerow({'File': name, 'Technique': 'BFS', 'ExecutionTime': execution_time_BFS, 'FinalState': final_states_BFS})

        # DFS
        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(technique_DFS)
        start_time = time.time()
        simgr.run()
        end_time = time.time()
        execution_time_DFS = end_time - start_time
        final_states_DFS = simgr.stashes
        results.append({'File': name, 'Technique': 'DFS', 'ExecutionTime': execution_time_DFS, 'FinalState': final_states_DFS})
        writer.writerow({'File': name, 'Technique': 'DFS', 'ExecutionTime': execution_time_DFS, 'FinalState': final_states_DFS})

        # KLEE
        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(technique_KLEE)
        start_time = time.time()
        simgr.run()
        end_time = time.time()
        execution_time_KLEE = end_time - start_time
        final_states_KLEE = simgr.stashes
        results.append({'File': name, 'Technique': 'KLEE', 'ExecutionTime': execution_time_KLEE, 'FinalState': final_states_KLEE})
        writer.writerow({'File': name, 'Technique': 'KLEE', 'ExecutionTime': execution_time_KLEE, 'FinalState': final_states_KLEE})

print("Analysis completed. Data written to", output_file_path)