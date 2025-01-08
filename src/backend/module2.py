# Importation des bibliothèques utiles
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time
import nltk
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.pipeline import make_pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from PIL import Image
from wordcloud import WordCloud, STOPWORDS, ImageColorGenerator
import pickle

# Téléchargement des ressources NLTK
import nltk
nltk.download('punkt')
nltk.download('stopwords')

# Chargement des données
df = pd.read_csv("input/phising-site-urls/phishing_site_urls.csv")
df.columns = [col.lower() for col in df.columns]

# Exploration des données
df.head()
df.info()
df.describe()
df.isnull().sum()
df['label'].value_counts()
df['label'].value_counts().plot(kind='bar')

# Préparation des données pour l'entraînement du modèle
X = df['url']
y = df['label']

# Division des données en ensembles d'entraînement et de test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Création du pipeline avec le vectoriseur de texte et le modèle de régression logistique
pipeline = make_pipeline(CountVectorizer(), LogisticRegression())

# Entraînement du modèle
pipeline.fit(X_train, y_train)

# Prédiction sur l'ensemble de test
y_pred = pipeline.predict(X_test)

# Évaluation du modèle
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Sauvegarde du modèle entraîné
with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(pipeline, f)