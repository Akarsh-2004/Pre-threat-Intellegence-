import joblib
import os
import numpy as np
import pandas as pd

# Ensure the path is correct
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, r"C:\Users\akars\OneDrive\Desktop\PTI\logic\IDSf\random_forest_model.pkl")
PREPROCESSOR_PATH = os.path.join(BASE_DIR, r"C:\Users\akars\OneDrive\Desktop\PTI\logic\IDSf\preprocessor.pkl")

# Check if files exist before loading
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
if not os.path.exists(PREPROCESSOR_PATH):
    raise FileNotFoundError(f"Preprocessor file not found: {PREPROCESSOR_PATH}")

# Load the trained model and preprocessor
model = joblib.load(MODEL_PATH)
preprocessor = joblib.load(PREPROCESSOR_PATH)

def analyze_log(file_path, log_type):
    """
    Analyzes the given log file using the IDS model.
    Args:
        file_path (str): Path to the log file.
        log_type (str): Type of log being analyzed.
    Returns:
        tuple: (bool, str) where bool indicates if intrusion was detected,
               and str provides analysis details.
    """
    try:
        # Read the log file (assumed CSV format for structured logs)
        df = pd.read_csv(file_path)
        
        # Preprocess data
        df_transformed = preprocessor.transform(df)
        
        # Predict using the trained IDS model
        predictions = model.predict(df_transformed)
        
        # Determine if intrusion detected
        intrusion_detected = np.any(predictions == 1)  # Assuming 1 means intrusion
        details = "Intrusion detected in log file!" if intrusion_detected else "No threats found."
        
        return intrusion_detected, details
    
    except Exception as e:
        return True, f"Error processing log file: {str(e)}"