import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Load dataset
df = pd.read_csv('input/phishing-csv/Email spam dataset.csv')
data = df.where((pd.notnull(df)), None)

# Convert categories to binary values
data.loc[data['Category'] == 'spam', 'Category'] = 0
data.loc[data['Category'] == 'ham', 'Category'] = 1

# Separate features and labels
x = data['Message']
y = data['Category']

# Split data into training and testing sets
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=3)

# Initialize TfidfVectorizer with correct parameters
feature_extraction = TfidfVectorizer(min_df=1, stop_words='english', lowercase=True)

# Transform the data
x_train_features = feature_extraction.fit_transform(x_train)
x_test_features = feature_extraction.transform(x_test)

# Convert labels to integers
y_train = y_train.astype('int')
y_test = y_test.astype('int')

# Train the model
model = LogisticRegression()
model.fit(x_train_features, y_train)

# Make predictions and calculate accuracy
prediction_on_training_data = model.predict(x_train_features)
accuracy_on_training_data = accuracy_score(y_train, prediction_on_training_data)

prediction_on_test_data = model.predict(x_test_features)
accuracy_on_test_data = accuracy_score(y_test, prediction_on_test_data)

# Print accuracy
print(accuracy_on_training_data)
print(accuracy_on_test_data)

# Save the model
import joblib
joblib.dump(model, 'output/phishing_model.joblib')
joblib.dump(feature_extraction, 'output/phishing_feature.joblib')

