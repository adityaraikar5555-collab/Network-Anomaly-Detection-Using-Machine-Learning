import os
import glob
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder


def load_dataset(data_path, sample_per_file=50000):
    csv_files = glob.glob(os.path.join(data_path, "*.csv"))

    if len(csv_files) == 0:
        raise FileNotFoundError("No CSV files found in data path.")

    df_list = []

    for file in csv_files:
        print("Loading:", os.path.basename(file))
        temp_df = pd.read_csv(file, low_memory=False)

        if sample_per_file is not None and len(temp_df) > sample_per_file:
            temp_df = temp_df.sample(n=sample_per_file, random_state=42)

        df_list.append(temp_df)

    df = pd.concat(df_list, ignore_index=True)
    return df


def clean_dataset(df):
    df.columns = df.columns.str.strip()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    df["Label"] = df["Label"].astype(str).str.strip()

    df["Label"] = df["Label"].apply(
        lambda x: "BENIGN" if x == "BENIGN" else "ATTACK"
    )

    le = LabelEncoder()
    df["Label"] = le.fit_transform(df["Label"])

    X = df.drop("Label", axis=1)
    y = df["Label"]

    return X, y, le