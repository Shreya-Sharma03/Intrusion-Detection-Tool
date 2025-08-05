import streamlit as st
import pandas as pd
import pickle

# Load the model and encoders
model = pickle.load(open("model.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))
label_encoders = pickle.load(open("label_encoders.pkl", "rb"))

st.title(" Intrusion Detection Tool")
st.write("Predict whether a network activity is **normal** or an **attack** based on input features.")

# Input form
with st.form("prediction_form"):
    duration = st.number_input("Duration", min_value=0)
    protocol_type = st.selectbox("Protocol Type", label_encoders["protocol_type"].classes_)
    
    src_bytes = st.number_input("Source Bytes", min_value=0)
    dst_bytes = st.number_input("Destination Bytes", min_value=0)

    submit = st.form_submit_button("Predict")

# Predict on submission
if submit:
    # Create input DataFrame
    input_df = pd.DataFrame([{
        'duration': duration,
        'protocol_type': protocol_type,
        'service': service,
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes
    }])

    # Encode categorical columns
    for col in ['protocol_type', 'service', 'flag']:
        le = label_encoders[col]
        input_df[col] = le.transform(input_df[col])

    # Scale numerical features
    X_scaled = scaler.transform(input_df)

    # Predict
    prediction = model.predict(X_scaled)
    result = target_le.inverse_transform(prediction)[0]

    # Show result
    st.subheader("🔍 Prediction:")
    if result == "normal":
        st.success("✅ This is a **normal** network activity.")
    else:
        st.error(f"⚠️ Detected **intrusion**: {result}")