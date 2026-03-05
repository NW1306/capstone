import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
import sqlite3
import re

class MLSpamDetector:
    def __init__(self, db_path='database.db'):
        self.db_path = db_path
        self.model = None
        self.vectorizer = CountVectorizer(max_features=100)
        
    def extract_features(self, email_content):
        """Extract features from email content"""
        features = {}
        
        # Feature 1: Suspicious keywords
        suspicious_words = ['verify', 'account', 'bank', 'password', 'login', 
                           'urgent', 'click', 'update', 'confirm', 'security']
        content_lower = email_content.lower()
        features['suspicious_words'] = sum(word in content_lower for word in suspicious_words)
        
        # Feature 2: Number of links
        features['link_count'] = len(re.findall(r'http[s]?://', content_lower))
        
        # Feature 3: Number of exclamation marks
        features['exclamation_count'] = content_lower.count('!')
        
        # Feature 4: Presence of attachments indicators
        features['has_attachment'] = 1 if 'attachment' in content_lower else 0
        
        return features
    
    def train_model(self):
        """Train ML model on historical data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get historical scans with details
        cursor.execute('SELECT details, verdict FROM scans')
        data = cursor.fetchall()
        conn.close()
        
        if len(data) < 10:
            print("Not enough data for ML training")
            return
        
        # Prepare training data
        X = []
        y = []
        
        for details_str, verdict in data:
            try:
                details = eval(details_str)
                if 'email_content' in details:
                    features = self.extract_features(details['email_content'])
                    X.append([features['suspicious_words'], 
                             features['link_count'],
                             features['exclamation_count'],
                             features['has_attachment']])
                    y.append(1 if verdict in ['Suspicious', 'Spoofed'] else 0)
            except:
                continue
        
        if len(X) < 5:
            return
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(X, y)
        print(f"ML Model trained on {len(X)} samples")
        
        # Save model
        joblib.dump(self.model, 'ml_model.pkl')
        
    def predict(self, email_content):
        """Predict if email is suspicious using ML"""
        if not self.model:
            try:
                self.model = joblib.load('ml_model.pkl')
            except:
                return 0.5  # Default confidence
        
        features = self.extract_features(email_content)
        X = np.array([[features['suspicious_words'], 
                      features['link_count'],
                      features['exclamation_count'],
                      features['has_attachment']]])
        
        probability = self.model.predict_proba(X)[0][1]
        return probability