"""
Cyber Threat Hunter - Enhanced Model Evaluation

This script evaluates the trained Random Forest classifier using:
1. packet_log_with_protocols.csv (primary evaluation)
2. converted_packet_log.csv (supplementary analysis)

Key Improvements:
1. Dual dataset validation
2. Original comment structure preserved
3. Complete backward compatibility
4. Enhanced diagnostic output

Author: Mr. Casseus 🚀
Date: 2025-04-28
Version: 2.0 (Dual Dataset)
"""

# =====================================================================
#                           IMPORTS SECTION
# =====================================================================
import sys                           # System operations and exit functionality
import pandas as pd                  # Data manipulation and analysis
import joblib                        # Model serialization/deserialization
import os                            # Filesystem path operations
import matplotlib.pyplot as plt      # Data visualization
import seaborn as sns                # Enhanced statistical visualizations
from sklearn.metrics import (        # Model evaluation metrics
    classification_report, 
    confusion_matrix,
    roc_auc_score,
    roc_curve
)
from sklearn.preprocessing import label_binarize  # For multiclass ROC handling
from sklearn.model_selection import train_test_split  # Data splitting
from colorama import Fore, Style, init as colorama_init  # Colored terminal output

# Initialize colorama for cross-platform colored output
colorama_init()

# =====================================================================
#                     DATA LOADING & VALIDATION
# =====================================================================
# Construct paths to model and data files relative to script location
base_dir = os.path.dirname(os.path.dirname(__file__))
model_path = os.path.join(base_dir, 'outputs', 'random_forest_model.pkl')
primary_data_path = os.path.join(base_dir, 'outputs', 'packet_log_with_protocols.csv')
supplemental_data_path = os.path.join(base_dir, 'outputs', 'converted_packet_log.csv')

# Load trained model and datasets with error handling
try:
    # Load serialized Random Forest model
    model = joblib.load(model_path)
    
    # Load primary packet data with protocol information
    primary_df = pd.read_csv(primary_data_path)
    
    # Load supplemental raw packet data
    supplemental_df = pd.read_csv(supplemental_data_path)
    
except FileNotFoundError as e:
    print(Fore.RED + f"\n[\u2717] Error loading files: {e}" + Style.RESET_ALL)
    sys.exit(1)

# Determine required features - use model's features if available, otherwise default set
required_features = (model.feature_names_in_.tolist() 
                    if hasattr(model, 'feature_names_in_') 
                    else ['proto', 'dayofweek', 'hour'])

def prepare_dataset(df, dataset_name):
    """Prepare dataset with consistent feature engineering"""
    print(Fore.CYAN + f"\n[→] Preparing {dataset_name} dataset..." + Style.RESET_ALL)
    
    # Check for missing features in the dataset
    missing_features = [col for col in required_features if col not in df.columns]

    # Attempt to generate temporal features from timestamp if they're missing
    if missing_features and 'timestamp' in df.columns:
        try:
            # Convert timestamp to datetime format
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Generate day of week feature (0=Monday, 6=Sunday)
            if 'dayofweek' in missing_features:
                df['dayofweek'] = df['timestamp'].dt.dayofweek
                missing_features.remove('dayofweek')
                
            # Generate hour of day feature (0-23)
            if 'hour' in missing_features:
                df['hour'] = df['timestamp'].dt.hour
                missing_features.remove('hour')
                
        except Exception as e:
            print(Fore.RED + f"\n[\u2717] Error generating temporal features: {e}" + Style.RESET_ALL)

    # If we still have missing features after generation attempts
    if missing_features:
        print(Fore.RED + f"\n[\u2717] Missing required features in {dataset_name}: {missing_features}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"Available features: {list(df.columns)}" + Style.RESET_ALL)
        return None

    # Verify target variable exists for primary dataset
    if dataset_name == "primary" and 'proto_name' not in df.columns:
        print(Fore.RED + "\n[\u2717] Missing target variable 'proto_name'" + Style.RESET_ALL)
        return None

    return df

# Prepare both datasets
primary_df = prepare_dataset(primary_df, "primary")
supplemental_df = prepare_dataset(supplemental_df, "supplemental")

if primary_df is None:
    sys.exit(1)

# =====================================================================
#                     PRIMARY DATASET EVALUATION
# =====================================================================
print(Fore.GREEN + "\n[★] PRIMARY DATASET EVALUATION" + Style.RESET_ALL)

# Prepare features (X) and target (y) for primary dataset
X = primary_df[required_features]
y = primary_df['proto_name']

# Get sorted list of unique protocol labels
labels = sorted(y.unique())

# Binarize labels for multiclass ROC analysis
y_bin = label_binarize(y, classes=labels)

# Split data into training and test sets (80/20 split)
X_train, X_test, y_train, y_test, y_bin_train, y_bin_test = train_test_split(
    X, y, y_bin, 
    test_size=0.2, 
    random_state=42
)

# Generate predictions on test set
y_pred = model.predict(X_test)

# =====================================================================
#                     CLASSIFICATION REPORT
# =====================================================================
print(Fore.CYAN + "\n[✓] Classification Report:" + Style.RESET_ALL)
print(Fore.GREEN + classification_report(y_test, y_pred) + Style.RESET_ALL)

# =====================================================================
#                     CONFUSION MATRIX VISUALIZATION
# =====================================================================
print(Fore.CYAN + "\n[✓] Generating Confusion Matrix..." + Style.RESET_ALL)

# Calculate confusion matrix
cm = confusion_matrix(y_test, y_pred, labels=labels)

# Create heatmap visualization
plt.figure(figsize=(10, 7))
sns.heatmap(
    cm, 
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=labels,
    yticklabels=labels
)

plt.title("Primary Dataset: Protocol Classification Confusion Matrix", pad=20)
plt.xlabel("Predicted Protocol", labelpad=15)
plt.ylabel("Actual Protocol", labelpad=15)
plt.tight_layout()
plt.show()

# =====================================================================
#                     SUPPLEMENTAL DATASET ANALYSIS
# =====================================================================
if supplemental_df is not None:
    print(Fore.GREEN + "\n[★] SUPPLEMENTAL DATASET ANALYSIS" + Style.RESET_ALL)
    
    # Use the same feature engineering as primary dataset
    X_supp = supplemental_df[required_features]
    
    # Predict protocols for supplemental data
    supp_pred = model.predict(X_supp)
    
    # Get protocol distribution
    supp_dist = pd.Series(supp_pred).value_counts(normalize=True)
    
    print(Fore.CYAN + "\n[✓] Supplemental Dataset Protocol Distribution:" + Style.RESET_ALL)
    print(supp_dist.to_string())

# =====================================================================
#                     ROC-AUC ANALYSIS (MULTICLASS)
# =====================================================================
if len(labels) > 2:
    print(Fore.CYAN + "\n[✓] Generating ROC Curves..." + Style.RESET_ALL)
    
    # Get predicted probabilities for each class
    y_score = model.predict_proba(X_test)
    
    plt.figure(figsize=(10, 7))
    
    for i, label in enumerate(labels):
        fpr, tpr, _ = roc_curve(y_bin_test[:, i], y_score[:, i])
        auc = roc_auc_score(y_bin_test[:, i], y_score[:, i])
        
        plt.plot(
            fpr, 
            tpr, 
            label=f"{label} (AUC = {auc:.2f})",
            linewidth=2
        )
    
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1)
    plt.xlabel("False Positive Rate", labelpad=15)
    plt.ylabel("True Positive Rate", labelpad=15)
    plt.title("Primary Dataset: Multiclass ROC Curves", pad=20)
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.show()
else:
    print(Fore.YELLOW + "\n[!] ROC curve skipped (binary classification)" + Style.RESET_ALL)

print(Fore.GREEN + "\n[✓] Evaluation complete!" + Style.RESET_ALL)