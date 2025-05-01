"""
Cyber Threat Hunter - Enhanced Model Training Script

Description:
-------------
This script trains a Random Forest classifier to predict network protocols,
now featuring:
1. Smart data loading from multiple file formats
2. Advanced feature engineering
3. Cross-validated model training
4. Detailed performance analytics

Key Improvements:
- Automatic handling of raw/mapped protocol data
- Temporal feature extraction
- Model performance tracking
- Feature importance visualization

Author: Mr. Casseus 🚀
Date: 2025-04-28
Version: 3.0
"""

# =====================================================================
#                           IMPORTS SECTION
# =====================================================================
import pandas as pd                  # For data manipulation and analysis
from sklearn.model_selection import (
    train_test_split,               # For splitting dataset
    cross_val_score                 # For cross-validation
)
from sklearn.ensemble import RandomForestClassifier  # ML model class
from sklearn.metrics import classification_report    # Model evaluation
import joblib                       # For model serialization
from colorama import Fore, Style, init  # Colored console output
import os                           # Filesystem operations
import sys                          # System exit handling
import numpy as np                  # Numerical operations (required by scikit-learn)

# Initialize colorama for colored output
init()

# =====================================================================
#                     PROTOCOL MAPPING CONSTANTS
# =====================================================================
# IANA standard protocol number to name mapping
PROTOCOL_MAP = {
    1: 'ICMP',      # Internet Control Message Protocol
    6: 'TCP',       # Transmission Control Protocol
    17: 'UDP',      # User Datagram Protocol
    2: 'IGMP',      # Internet Group Management Protocol
    58: 'IPv6-ICMP' # ICMP for IPv6
}

# =====================================================================
#                     DATA LOADING AND VALIDATION
# =====================================================================
def load_training_data():
    """
    Smart data loader that handles multiple input formats:
    - converted_packet_log.csv (raw numbers)
    - packet_log_with_protocols.csv (pre-mapped names)
    - suspicious_packets_log.txt (raw sniffer output)
    
    Returns:
        pandas.DataFrame: Validated dataset
    Raises:
        SystemExit: If no valid data found
    """
    base_dir = os.path.dirname(os.path.dirname(__file__))
    possible_files = [
        os.path.join(base_dir, 'outputs', 'converted_packet_log.csv'),
        os.path.join(base_dir, 'outputs', 'packet_log_with_protocols.csv'),
        os.path.join(base_dir, 'outputs', 'suspicious_packets_log.txt')
    ]
    
    for file_path in possible_files:
        if os.path.exists(file_path):
            print(Fore.CYAN + f"[✓] Found data file: {file_path}" + Style.RESET_ALL)
            try:
                # Handle different file formats
                if file_path.endswith('.txt'):
                    df = pd.read_csv(file_path, sep='\t', header=None,
                                   names=['timestamp', 'proto', 'src', 'dst'])
                else:
                    df = pd.read_csv(file_path)
                
                # Ensure protocol names exist
                if 'proto_name' not in df.columns:
                    print(Fore.YELLOW + "[!] Mapping protocol names..." + Style.RESET_ALL)
                    df['proto_name'] = df['proto'].map(PROTOCOL_MAP).fillna('OTHER')
                
                return df
            except Exception as e:
                print(Fore.YELLOW + f"[!] Error reading {file_path}: {e}" + Style.RESET_ALL)
                continue
    
    # No valid files found
    print(Fore.RED + "[✗] No valid training data found!" + Style.RESET_ALL)
    print("Please run protocol mapping or packet capture first")
    sys.exit(1)

# =====================================================================
#                     FEATURE ENGINEERING
# =====================================================================
def create_features(df):
    """
    Creates enhanced feature set from raw data:
    - Basic protocol numbers
    - Temporal features (if timestamps available)
    - Packet size metrics
    
    Args:
        df (DataFrame): Raw input data
    Returns:
        DataFrame: Engineered features
    """
    features = df[['proto']].copy()
    
    # Extract time-based features if available
    if 'timestamp' in df.columns:
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            features['hour'] = df['timestamp'].dt.hour
            features['dayofweek'] = df['timestamp'].dt.dayofweek
        except Exception as e:
            print(Fore.YELLOW + f"[!] Could not parse timestamps: {e}" + Style.RESET_ALL)
    
    # Add packet length if available
    if 'length' in df.columns:
        features['length'] = df['length']
    
    return features

# =====================================================================
#                     MODEL TRAINING AND EVALUATION
# =====================================================================
def train_and_evaluate(X_train, y_train, X_test, y_test):
    """
    Trains Random Forest model with cross-validation,
    evaluates performance, and returns trained model
    
    Args:
        X_train, y_train: Training data
        X_test, y_test: Test data
    Returns:
        RandomForestClassifier: Trained model
    """
    print(Fore.CYAN + "[🔄] Training model..." + Style.RESET_ALL)
    
    # Initialize model with optimized parameters
    model = RandomForestClassifier(
        n_estimators=150,        # Number of decision trees
        max_depth=None,          # Let trees grow fully
        min_samples_split=5,     # Prevent overfitting
        class_weight='balanced', # Handle imbalanced classes
        random_state=42,         # Reproducible results
        n_jobs=-1                # Use all CPU cores
    )
    
    # 5-fold cross-validation
    print(Fore.BLUE + "[ℹ] Running cross-validation..." + Style.RESET_ALL)
    cv_scores = cross_val_score(model, X_train, y_train, 
                               cv=5, scoring='f1_weighted')
    
    # Print CV results using numpy for precise formatting
    print(Fore.BLUE + f"CV Scores: {np.round(cv_scores, 4)}" + Style.RESET_ALL)
    print(Fore.BLUE + f"Mean CV F1: {np.mean(cv_scores):.4f}" + Style.RESET_ALL)
    
    # Train final model
    model.fit(X_train, y_train)
    
    # Evaluate on test set
    print(Fore.GREEN + "\n[✓] Test Set Performance:" + Style.RESET_ALL)
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, digits=4))
    
    return model

# =====================================================================
#                     MAIN TRAINING WORKFLOW
# =====================================================================
def main():
    """Complete training workflow from data loading to model saving"""
    print(Fore.CYAN + "[🚀] Starting CyberHunter Model Training" + Style.RESET_ALL)
    
    # 1. Data Loading
    df = load_training_data()
    
    # 2. Feature Engineering
    print(Fore.CYAN + "[🔄] Creating features..." + Style.RESET_ALL)
    X = create_features(df)
    y = df['proto_name']
    
    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,          # 20% for testing
        random_state=42,        # Reproducible splits
        stratify=y              # Maintain class balance
    )
    
    # 4. Model Training
    model = train_and_evaluate(X_train, y_train, X_test, y_test)
    
    # 5. Save Model
    model_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'outputs',
        'random_forest_model.pkl'
    )
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(Fore.GREEN + f"\n[✓] Model saved to: {model_path}" + Style.RESET_ALL)
    
    # 6. Feature Importance
    print(Fore.BLUE + "\n[ℹ] Feature Importances:" + Style.RESET_ALL)
    for name, importance in zip(X.columns, model.feature_importances_):
        print(f"{name}: {importance:.4f}")

if __name__ == "__main__":
    main()