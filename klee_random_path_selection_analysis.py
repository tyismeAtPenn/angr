import angr
import time
import os

directory_path = './crackme'
output_file_path = 'analysis_output.txt'

# Get all file names in the directory
file_names = sorted([os.path.join(directory_path, f) for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))])
technique_DFS = angr.exploration_techniques.DFS()
technique_KLEE = angr.exploration_techniques.KLEERandPathSelection()


with open(output_file_path, 'w') as output_file:
    output_file.write("Analysis Results\n")
    output_file.write("-----------------\n")

    for name in file_names:
        output_file.write(f"\nFile: {name}\n")
        proj = angr.Project(name, auto_load_libs = False)
        state = proj.factory.entry_state()

        simgr = proj.factory.simulation_manager(state)
        start_time = time.time()
        simgr.run()
        end_time = time.time()
        final_states_BFS = simgr.deadended
        execution_time_technique_BFS = end_time - start_time

        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(technique_DFS)
        start_time = time.time()
        simgr.run()
        end_time = time.time()
        final_states_DFS = simgr.deadended
        execution_time_technique_DFS = end_time - start_time

        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(technique_KLEE)
        start_time = time.time()
        simgr.run()
        end_time = time.time()
        final_states_KLEE = simgr.deadended
        execution_time_technique_KLEE = end_time - start_time

        output_file.write(f"Final State - BFS: {final_states_BFS}\n")
        output_file.write(f"Final State - DFS: {final_states_BFS}\n")
        output_file.write(f"Final State - KLEE: {final_states_KLEE}\n\n")

        output_file.write(f"Execution Time - BFS: {execution_time_technique_BFS} seconds\n")
        output_file.write(f"Execution Time - DFS: {execution_time_technique_DFS} seconds\n")
        output_file.write(f"Execution Time - KLEE: {execution_time_technique_KLEE} seconds\n")
        output_file.write(f"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")

