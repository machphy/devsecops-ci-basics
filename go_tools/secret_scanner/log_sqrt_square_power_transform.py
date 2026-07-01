import numpy as np
import pandas as pd

# Sample dataset
df = pd.DataFrame({
    "price": [1000, 1500, 2500, 4000, 8000],
    "curb_weight": [1800, 2200, 2600, 3000, 3400]
})

print("Original Data")
print(df)

# -----------------------------------
# 1. Log Transformation
# -----------------------------------
# Natural logarithm
df["price_log"] = np.log(df["price"])

# If your data contains zeros, use:
# df["price_log"] = np.log1p(df["price"])

# -----------------------------------
# 2. Square Root Transformation
# -----------------------------------
df["curb_weight_sqrt"] = np.sqrt(df["curb_weight"])

# -----------------------------------
# 3. Square Transformation
# -----------------------------------
df["price_square"] = np.square(df["price"])

# -----------------------------------
# 4. Exponential (Power) Transformation
# -----------------------------------
# exponent = 0.5 is equivalent to square root
df["price_power_05"] = np.power(df["price"], 0.5)

# Example with exponent = 2
df["price_power_2"] = np.power(df["price"], 2)

print("\nTransformed Data")
print(df)