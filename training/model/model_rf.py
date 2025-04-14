import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

# Define the base path and list of files
base_path = '/home/wifi/sdn/training/dataset'
files = [
    ('normal_icmp1.csv', 'Normal_ICMP'),
    ('normal_icmp2.csv', 'Normal_ICMP'),
    ('normal_tcp1.csv', 'Normal_TCP'),
    ('normal_tcp2.csv', 'Normal_TCP'),
    ('ddos_icmp1.csv', 'DDoS_ICMP'),
    ('ddos_icmp2.csv', 'DDoS_ICMP'),
    ('ddos_icmp3.csv', 'DDoS_ICMP'),
    ('ddos_icmp4.csv', 'DDoS_ICMP'),
    ('ddos_tcp1.csv', 'DDoS_TCP'),
    ('ddos_tcp2.csv', 'DDoS_TCP'),
    ('ddos_tcp3.csv', 'DDoS_TCP'),
    ('ddos_tcp4.csv', 'DDoS_TCP')
]

# Define protocol mapping
protocol_mapping = {
    'Normal_ICMP': 1,  # ICMP
    'DDoS_ICMP': 1,   # ICMP
    'Normal_TCP': 6,   # TCP
    'DDoS_TCP': 6      # TCP
}

# Combine data from all files
dataframes = []
for file_name, label in files:
    file_path = os.path.join(base_path, file_name)
    try:
        df = pd.read_csv(file_path)
        # Add Label and Protocols columns
        df['Label'] = label
        df['Protocols'] = protocol_mapping[label]
        dataframes.append(df)
    except Exception as e:
        print(f"Failed to load {file_name}: {e}")

# Concatenate all dataframes
combined_df = pd.concat(dataframes, ignore_index=True)

# Exclude rows where duration_sec == 0 and duration_nsec == 0
combined_df = combined_df[~((combined_df.get('Duration (sec)', 0) == 0) & (combined_df.get('Duration (nsec)', 0) == 0))]

# Check for required columns
required_columns = ['Packet Count', 'Byte Count', 'Packet Rate', 'Byte Rate', 'CPU utilization', 'Protocols', 'Label']
for col in required_columns:
    if col not in combined_df.columns:
        print(f"Column {col} is missing in the data!")
        exit()

# Save combined data
output_path = '/home/wifi/sdn/training/dataset/dataset.csv'
combined_df.to_csv(output_path, index=False)
print(f"Created {output_path} successfully")

# Check data distribution
print("Data count by Protocols:")
print(combined_df['Protocols'].value_counts())
print("\nData count by Protocols and Label:")
print(combined_df.groupby('Protocols')['Label'].value_counts())

# Define features and target
features = ['Packet Count', 'Byte Count', 'Packet Rate', 'Byte Rate', 'CPU utilization']
X = combined_df[features]
y = combined_df['Label']

# Define protocol map for training
protocol_map = {
    1: ['DDoS_ICMP', 'Normal_ICMP'],  # ICMP
    6: ['DDoS_TCP', 'Normal_TCP']     # TCP
}

# Train models for each protocol
for protocol, valid_labels in protocol_map.items():
    # Filter data for this protocol
    df_protocol = combined_df[combined_df['Protocols'] == protocol].copy()
    
    if df_protocol.empty:
        print(f"No data for protocol {protocol}. Skipping...")
        continue

    # Features and target
    X_protocol = df_protocol[features]
    y_protocol = df_protocol['Label']

    # Check available classes
    unique_classes = y_protocol.unique()
    print(f"\nProtocol {protocol} has classes: {unique_classes}")
    
    if len(unique_classes) < 2:
        print(f"Not enough classes for protocol {protocol} (found {len(unique_classes)} classes). Skipping...")
        continue

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_protocol, y_protocol, test_size=0.2, random_state=42
    )

    # Train Random Forest model
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)

    # Evaluate model
    y_pred = rf_model.predict(X_test)
    print(f"\nModel for protocol {protocol}:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print(classification_report(y_test, y_pred))

    # Save model
    model_path = f'/home/wifi/sdn/training/model/rf_model_{protocol}.joblib'
    joblib.dump(rf_model, model_path)
    print(f"Model for protocol {protocol} saved to {model_path}")

print("\nAll models trained and saved successfully!")
