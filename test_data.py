import pandas as pd

try:
    # 1. Loading the dataset file
    df = pd.read_csv('dataset.csv') 
    
    print("Success: Dataset Loaded!")
    print("-" * 30)
    
    # 2. Displaying the first 5 rows to see the data structure
    print("Preview of the Data:")
    print(df.head())   #show the 5 first of row from dataset
    
    print("-" * 30)
    
    # 3. Showing the number of records and features
    print(f"Total Records: {df.shape[0]}")
    print(f"Total Features: {df.shape[1]}")
    
    # 4. Checking the distribution of (Safe vs Phishing) links
    print("-" * 30)
    print("Target Distribution (1 = Safe, -1 = Phishing):")
    print(df['Result'].value_counts())

except Exception as e:
    print(f"Error: {e}")



    