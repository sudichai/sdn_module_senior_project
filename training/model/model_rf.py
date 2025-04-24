import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns

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
    ('ddos_tcp4.csv', 'DDoS_TCP'),
    ('all_icmp.csv', None),  # Unlabeled, to be labeled
    ('all_tcp1.csv', None),  # Unlabeled, to be labeled
    ('all_tcp2.csv', None),   # Unlabeled, to be labeled
    ('all_tcp3.csv', None)   # Unlabeled, to be labeled
]

# Define protocol mapping
protocol_mapping = {
    'Normal_ICMP': 1,  # ICMP
    'DDoS_ICMP': 1,   # ICMP
    'Normal_TCP': 6,   # TCP
    'DDoS_TCP': 6,     # TCP
    'all_icmp': 1,     # ICMP
    'all_tcp1': 6,     # TCP
    'all_tcp2': 6      # TCP
}

# Function to label unlabeled data based on Eth Src and Eth Dst
def label_unlabeled_data(df):
    ddos_condition = (
        ((df['Ethernet Src'] == '00:00:00:00:00:12') & (df['Ethernet Dst'] == '00:00:00:00:00:13')) |
        ((df['Ethernet Dst'] == '00:00:00:00:00:12') & (df['Ethernet Src'] == '00:00:00:00:00:13'))
    )
    normal_condition = (
        ((df['Ethernet Src'] == '00:00:00:00:00:11') & (df['Ethernet Dst'] == '00:00:00:00:00:13')) |
        ((df['Ethernet Dst'] == '00:00:00:00:00:11') & (df['Ethernet Src'] == '00:00:00:00:00:13'))
    )
    
    # Assign labels based on conditions
    df.loc[ddos_condition, 'Label'] = 'DDoS_' + ('ICMP' if df['Protocols'].iloc[0] == 1 else 'TCP')
    df.loc[normal_condition, 'Label'] = 'Normal_' + ('ICMP' if df['Protocols'].iloc[0] == 1 else 'TCP')
    
    # Drop rows that don't match either condition
    df = df.dropna(subset=['Label'])
    return df

# Combine data from all files
dataframes = []
for file_name, label in files:
    file_path = os.path.join(base_path, file_name)
    try:
        df = pd.read_csv(file_path)
        # Add Protocols column
        df['Protocols'] = protocol_mapping.get(label, protocol_mapping.get(file_name.split('.')[0]))
        # Add Label column
        if label is None:  # Unlabeled files
            df = label_unlabeled_data(df)
        else:
            df['Label'] = label
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

    # Split data: 70% train, 30% test
    X_train, X_test, y_train, y_test = train_test_split(
        X_protocol, y_protocol, test_size=0.3, random_state=42
    )

    # Train Random Forest model with 70% data
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)

    # Evaluate model on test set (30%)
    y_pred = rf_model.predict(X_test)
    print(f"\nModel for protocol {protocol} (Train 70%, Test 30%):")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")

    # Plot Confusion Matrix
    cm = confusion_matrix(y_test, y_pred, labels=valid_labels)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=valid_labels, yticklabels=valid_labels)
    plt.title(f'Confusion Matrix for Protocol {protocol}')
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.savefig(f'confusion_matrix_protocol_{protocol}.png')
    plt.close()

    # Calculate classification metrics and display as a table
    report = classification_report(y_test, y_pred, output_dict=True)
    metrics_df = pd.DataFrame(report).transpose()
    print(f"\nClassification Report for Protocol {protocol}:")
    print(metrics_df[['precision', 'recall', 'f1-score', 'support']])

    # Retrain the model with 100% data
    print(f"\nRetraining model for protocol {protocol} with 100% data...")
    rf_model.fit(X_protocol, y_protocol)

    # Save the retrained model
    model_path = f'/home/wifi/sdn/training/model/rf_model_{protocol}.joblib'
    joblib.dump(rf_model, model_path)
    print(f"Model for protocol {protocol} saved to {model_path}")

print("\nAll models trained, evaluated, and saved successfully!")
