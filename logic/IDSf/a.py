import pandas as pd
import joblib
import numpy as np

# Load the trained model and preprocessor
model = joblib.load('random_forest_model.pkl')
preprocessor = joblib.load('preprocessor.pkl')

# Load the correct feature column names from training
feature_columns = joblib.load('feature_columns.pkl')  # Ensure this matches training

# Sample input data (Ensure correct number of features)
input_data = [[0, 'tcp', 'telnet', 'SF', 129, 174, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 255, 255, 1, 0, 0, 0, 0.01, 0.01, 0.02, 0.02]]

# Debug: Check the number of features
print(f"Expected {len(feature_columns)} columns, but input has {len(input_data[0])} values.")

# Convert input_data into a DataFrame
input_df = pd.DataFrame(input_data, columns=feature_columns)

# Apply the preprocessor (OneHotEncoder & StandardScaler)
input_transformed = preprocessor.transform(input_df)

# Make prediction
prediction = model.predict(input_transformed)

# Print result
print("Prediction:", "attack" if prediction[0] == 1 else "normal")
