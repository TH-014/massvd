import pandas as pd
import numpy as np

def sample_csv_normally(input_file, output_file, sample_size=100):
    # Load the dataset
    df = pd.read_csv(input_file)
    num_rows = len(df)
    
    if num_rows < sample_size:
        raise ValueError("The dataset has fewer rows than the requested sample size.")

    # Define parameters for the normal distribution
    # Mean (mu) is the middle of the range
    mu = num_rows / 2
    # Standard deviation (sigma): 
    # Setting sigma to num_rows/6 ensures ~99.7% of values fall within [0, num_rows]
    sigma = num_rows / 6

    indices = []
    while len(indices) < sample_size:
        # Generate random samples from a normal distribution
        samples = np.random.normal(loc=mu, scale=sigma, size=sample_size * 2)
        
        # Round to nearest integer and filter those within valid range [0, num_rows-1]
        valid_indices = samples.astype(int)
        valid_indices = valid_indices[(valid_indices >= 0) & (valid_indices < num_rows)]
        
        # Add to our list and keep only unique values
        indices.extend(valid_indices.tolist())
        indices = list(set(indices))

    # Pick exactly the requested number of unique indices
    final_indices = indices[:sample_size]
    
    # Select the rows and save to a new CSV
    sampled_df = df.iloc[final_indices]
    sampled_df.to_csv(output_file, index=False)
    
    print(f"Successfully saved {sample_size} normally distributed rows to {output_file}")

# Usage
sample_csv_normally('juliet-cpp-1.3.csv', 'test_1.csv')