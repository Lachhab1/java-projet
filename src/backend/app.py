from flask import Flask, request, jsonify
import pickle
import joblib
import os

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({'message': 'Hello, World!'})

@app.route('/predict', methods=['POST'])
def predict():
    url = request.json['url']
    with open('phishing_model.pkl', 'rb') as f:
        pipeline = pickle.load(f)
    prediction = pipeline.predict([url])
    return jsonify({'prediction': prediction[0]})

@app.route('/predict_email', methods=['POST'])
def predict_email():
    email_text = request.json['email_text']
    model = joblib.load('output/phishing_model.joblib')
    feature = joblib.load('output/phishing_feature.joblib')
    email_text = feature.transform([email_text])
    prediction = model.predict(email_text)
    return jsonify({'prediction': 'Phishing' if prediction[0] == 0 else 'Not Phishing'})

@app.route('/inbox', methods=['GET'])
def inbox():
    # Simulate fetching emails from a service
    emails = [
        {'id': '1', 'snippet': 'This is a test email snippet', 'body': 'This is the body of the test email'}
    ]
    phishing_emails = detect_phishing(emails)
    return jsonify({'emails': phishing_emails})

@app.route('/inboxes', methods=['GET'])
def inboxes():
    # Simulate fetching multiple emails from a service
    emails = [
        {'id': '1', 'snippet': 'This is a test email snippet', 'body': 'This is the body of the test email'},
        {'id': '2', 'snippet': 'Another test email snippet', 'body': 'This is the body of another test email'}
    ]
    return jsonify({'emails': emails})

@app.route('/phishing_inbox', methods=['GET'])
def phishing_inbox():
    # Simulate fetching emails from a service
    emails = [
        {'id': '1', 'snippet': 'This is a test email snippet', 'body': 'This is the body of the test email'}
    ]
    phishing_emails = detect_phishing(emails)
    return jsonify({'emails': phishing_emails})

def detect_phishing(emails):
    phishing_emails = []
    model = joblib.load('output/phishing_model.joblib')
    feature = joblib.load('output/phishing_feature.joblib')
    
    for email in emails:
        email_text = email['snippet']
        email_text = feature.transform([email_text])
        prediction = model.predict(email_text)
        if prediction[0] == 0:
            phishing_emails.append(email)
    
    return phishing_emails

if __name__ == '__main__':
    app.run(port=8000)