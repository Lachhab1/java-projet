# module_phishing.py

import pandas as pd
import numpy as np
import re
import tldextract
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Encodage des caractères
def encode_domain(domain):
    try:
        domain = domain.encode('idna').decode('ascii')
    except UnicodeError:
        domain = re.sub(r'[^\x00-\x7f]', r'', domain)
    return domain

# Fonction pour extraire les fonctionnalités des URLs
def extract_features(url):
    # Extraire les fonctionnalités lexicales
    url_length = len(url)
    num_dots = url.count('.')
    num_at = url.count('@')
    num_qmark = url.count('?')
    num_eq = url.count('=')
    num_numbers = sum(c.isdigit() for c in url)

    # Extraire les informations sur le domaine
    ext = tldextract.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain.split('.') if ext.subdomain != '' else []
    num_subdomains = len(subdomain)

    # Vérifier si HTTPS est utilisé
    is_https = 1 if url.startswith('https://') else 0

    # Vérifier les caractères suspects
    suspicious_chars = re.findall(r'[@\-_]', url)
    num_suspicious_chars = len(suspicious_chars)

    # Vérifier si l'URL contient une adresse IP
    try:
        urlparse(url).hostname.split('.')[-1].isdigit()
        has_ip = 1
    except:
        has_ip = 0

    # Agréger les fonctionnalités
    features = [url_length, num_dots, num_at, num_subdomains, num_qmark, num_eq, num_numbers,
                is_https, num_suspicious_chars, has_ip]
    return features

def train_phishing_model(data_path):
    # Chargement des données
    df = pd.read_csv(data_path)
    df.columns = [col.lower() for col in df.columns]

    # Extraire les fonctionnalités des URLs
    X = df['url'].apply(extract_features)
    X = np.vstack(X)  # Convertir la liste de tableaux en un tableau 2D
    y = df['label']  # 0 pour légitime, 1 pour phishing (ajuster en fonction du nom de colonne réel)

    # Diviser les données en ensembles d'entraînement et de test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Entraîner le modèle Random Forest
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)

    # Évaluer les performances du modèle
    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)

    return rf_model, accuracy, report