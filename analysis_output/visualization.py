import pandas as pd
import matplotlib.pyplot as plt

# Read the CSV file
df = pd.read_csv('analysis_output.csv')

# Plotting for each program
for name in df['File'].unique():
    program_data = df[df['File'] == name]
    program_data.plot(kind='bar', x='Technique', y='ExecutionTime', color=['blue', 'green', 'red'], legend=False)
    plt.xlabel('Exploration Techniques')
    plt.ylabel('Execution Time (seconds)')
    plt.title(f'Execution Time Comparison for {name}')
    plt.show()
