import pandas as pd
import logging

# Setup logging
logging.basicConfig(
    filename="../logs/feature_extraction.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# File paths
metadata_file = "../data/static/metadata_collection.csv"
features_file = "../data/static/features.csv"

def preprocess_metadata():
    logging.info("Starting metadata preprocessing...")

    try:
        # Load metadata into a DataFrame
        df = pd.read_csv(metadata_file)
        logging.info(f"Loaded {len(df)} rows from {metadata_file}")

        # Handle missing values (fill with 'N/A')
        df.fillna("N/A", inplace=True)
        logging.info("Handled missing values by filling with 'N/A'")

        # Remove duplicate rows
        before_dedup = len(df)
        df.drop_duplicates(inplace=True)
        after_dedup = len(df)
        logging.info(f"Removed {before_dedup - after_dedup} duplicate rows")

        # Save the preprocessed data
        df.to_csv(features_file, index=False)
        logging.info(f"Preprocessed metadata saved to {features_file}")

    except Exception as e:
        logging.error(f"Error during metadata preprocessing: {e}")
        raise

if __name__ == "__main__":
    preprocess_metadata()
