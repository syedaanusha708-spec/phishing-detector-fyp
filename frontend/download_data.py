import os
import pandas as pd
import kagglehub

# 1. Set Credentials
os.environ['KAGGLE_USERNAME'] = "Syeda Anusha"
os.environ['KAGGLE_KEY'] = "fyp_1"

print("Fetching dataset from Kaggle cache...")

# 2. Get local dataset path
path = kagglehub.dataset_download("hassaanmustafavi/phishing-urls-dataset")
files = os.listdir(path)
csv_files = [f for f in files if f.endswith('.csv')]

if csv_files:
    target_csv = os.path.join(path, csv_files[0])
    df = pd.read_csv(target_csv)
    
    # Check total available rows and sample 20,000 for better balance
    sample_size = min(20000, len(df))
    df_20000 = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
    
    # Save the expanded dataset
    output_path = "kaggle_1000_dataset.csv"
    df_20000.to_csv(output_path, index=False)
    
    print(f"\nSUCCESS! Updated dataset created with {len(df_20000)} rows!")
    print(f"Saved to: {output_path}")
else:
    print("Error: No CSV file found.")