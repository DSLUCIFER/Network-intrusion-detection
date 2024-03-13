from flask import Flask, render_template, request
from scapy.all import sniff, stop_filter
import numpy as np
import joblib

app = Flask(__name__)

# Load the pre-trained SVM model
svm_model = joblib.load('svm_model.joblib')

# Global variable to indicate whether packet capture is ongoing
packet_capture_running = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global packet_capture_running
    packet_capture_running = True
    


    #connect with the preprocessed_packet file or

    # Function to preprocess packet data and make predictions
    def process_packet(packet):
        if packet_capture_running:
            # Preprocess packet data 
           
            packet_data = extract_features(packet)
            # Make predictions using SVM model
            prediction = svm_model.predict(packet_data.reshape(1, -1))
            print("Intrusion detected:", prediction)
    
    # Start packet capture
    sniff(prn=process_packet, stop_filter=lambda _: not packet_capture_running)

    return "Packet capture started"

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global packet_capture_running
    packet_capture_running = False
    return "Packet capture stopped"

@app.route('/check_intrusion', methods=['POST'])
def check_intrusion():
    #statements to check intrusion 
    #based on the requirement
    return "Intrusion checked"

def extract_features(packet):
    # Extract features from the packet ( based on the dataset)
    # example:
    features = np.array([...])  # Extracted features as a numpy array
    return features

if __name__ == '__main__':
    app.run(debug=True)
