import streamlit as st
import pandas as pd
import pickle

# Load models
model = pickle.load(open('model.pkl', 'rb'))
scaler = pickle.load(open('scaler.pkl', 'rb'))
label_encoders = pickle.load(open('label_encoders.pkl', 'rb'))

st.title("Intrusion Detection")

# Input widgets
network_packet_size = st.number_input("Packet Size", 500)
protocol_type = st.selectbox("Protocol Type", ["TCP", "UDP", "ICMP"])
login_attempts = st.number_input("Login Attempts", 2)
session_duration = st.number_input("Session Duration", 450.0)
encryption_used = st.selectbox("Encryption", ["DES", "AES", "NaN"])
ip_reputation_score = st.number_input("IP Score", 0.5)
failed_logins = st.number_input("Failed Logins", 0)
browser_type = st.selectbox("Browser", ["Firefox", "Edge", "Chrome"])
unusual_time_access = st.selectbox("Unusual Time", [0, 1])

if st.button("Predict"):
    # Create DataFrame
    input_df = pd.DataFrame([[
        0, # Placeholder for session_id to match original columns
        network_packet_size,
        protocol_type,
        login_attempts,
        session_duration,
        encryption_used,
        ip_reputation_score,
        failed_logins,
        browser_type,
        unusual_time_access
    ]], columns=['session_id', 'network_packet_size', 'protocol_type', 
                 'login_attempts', 'session_duration', 'encryption_used', 
                 'ip_reputation_score', 'failed_logins', 'browser_type', 
                 'unusual_time_access'])

    # Encode and scale
    input_df['protocol_type'] = label_encoders['protocol_type'].transform(input_df['protocol_type'])
    input_df['encryption_used'] = label_encoders['encryption_used'].transform(input_df['encryption_used'])
    input_df['browser_type'] = label_encoders['browser_type'].transform(input_df['browser_type'])
    scaled_data = scaler.transform(input_df)
    
    # Predict and show result
    prediction = model.predict(scaled_data)[0]
    
    if prediction == 1:
        st.error("Attack Detected")
    else:
        st.success("Normal Activity")