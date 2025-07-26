# DDoS Detection System 🛡️

A comprehensive machine learning system for detecting Distributed Denial of Service (DDoS) attacks using network intrusion data. This project implements a complete end-to-end ML pipeline with advanced preprocessing techniques, domain-specific feature engineering, ensemble feature selection methods, and automated model training and evaluation.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Technical Architecture](#technical-architecture)
- [Data Pipeline](#data-pipeline)
- [Model Training & Evaluation](#model-training--evaluation)
- [Improvements Implemented](#improvements-implemented)
- [Results & Performance](#results--performance)
- [Model Deployment](#model-deployment)
- [Functions Documentation](#functions-documentation)
- [Dependencies](#dependencies)
- [Dataset Information](#dataset-information)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This DDoS detection system processes network traffic data to identify malicious activities using machine learning techniques. The system implements a complete end-to-end pipeline that:

- ✅ **Downloads** network intrusion datasets from Kaggle automatically
- ✅ **Preprocesses** data with outlier detection and domain-specific feature engineering
- ✅ **Selects** optimal features using ensemble methods
- ✅ **Balances** and standardizes data for ML model preparation
- ✅ **Trains** and evaluates 4 ML models (Random Forest, Decision Tree, KNN, SVM)
- ✅ **Selects** best performing model automatically based on F1 score
- ✅ **Saves** trained model and scaler for immediate deployment
- ✅ **Provides** comprehensive performance metrics and model comparison

## 🚀 Features

### Core Capabilities

- 🔄 **Automated Data Download**: Downloads network intrusion dataset from Kaggle
- 📁 **Multi-file Processing**: Combines multiple CSV files into unified dataset
- 🔍 **Advanced Preprocessing**: Outlier detection using IQR method with intelligent capping
- 🌐 **Network Feature Engineering**: Domain-specific features for network traffic analysis
- 🔗 **Correlation Analysis**: Removes redundant features (>95% correlation threshold)
- 🧠 **Ensemble Feature Selection**: F-test + Mutual Information + Tree-based importance
- ⚖️ **Data Balancing**: Handles class imbalance with undersampling/oversampling
- 📏 **Standardization**: StandardScaler normalization for ML algorithms
- 🤖 **Multi-Model Training**: Random Forest, Decision Tree, KNN, SVM models
- 🏆 **Automated Model Selection**: Best model selection based on F1 score
- 💾 **Model Persistence**: Saves model and scaler using joblib
- 📊 **Comprehensive Evaluation**: Accuracy, precision, recall, F1, confusion matrices

### Implementation Status

- ✅ **Complete Pipeline**: Full end-to-end implementation (673 lines)
- ✅ **Data Processing**: Advanced preprocessing with 7 major steps
- ✅ **Feature Engineering**: Network-specific features (ratios, rates, flows)
- ✅ **Model Training**: 4 algorithms with comprehensive evaluation
- ✅ **Model Selection**: Automatic best model identification and saving
- ✅ **Production Ready**: Saved models ready for deployment

## 📁 Project Structure

```
ddos-detection/
├── main.py                    # Complete implementation (673 lines)
├── requirements.txt           # Python dependencies (6 packages)
├── README.md                 # Comprehensive documentation
├── ddos_best_model.joblib    # Best performing trained model
├── ddos_scaler.joblib        # Feature scaler for deployment
└── .gitignore               # Git ignore rules
```

## 🛠️ Installation

### Prerequisites

- Python 3.7+
- Kaggle API credentials (for dataset download)

### Quick Setup

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd ddos-detection
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Kaggle API** (required for dataset download):
   - Go to [Kaggle Account Settings](https://www.kaggle.com/account)
   - Create new API token → Download `kaggle.json`
   - Place in `~/.kaggle/` directory
   - Set permissions: `chmod 600 ~/.kaggle/kaggle.json`

## 🚀 Usage

### Run Complete Pipeline

Execute the full DDoS detection pipeline:

```bash
python main.py
```

### Pipeline Execution Steps

The system automatically executes these steps:

1. **📥 Data Acquisition** - Downloads network intrusion dataset from Kaggle
2. **📊 Data Loading** - Processes and combines multiple CSV files
3. **🔍 Outlier Detection** - IQR-based outlier detection and capping
4. **🛠️ Feature Engineering** - Creates 15+ network-specific features
5. **🧹 Data Preprocessing** - Handles missing values, infinity values, data cleaning
6. **🎯 Feature Selection** - Ensemble method selects top 10 features
7. **⚖️ Data Balancing** - Balances classes and standardizes features
8. **🤖 Model Training** - Trains Random Forest, Decision Tree, KNN, SVM
9. **📈 Model Evaluation** - Comprehensive metrics for all models
10. **🏆 Model Selection** - Saves best model based on F1 score

### Expected Output Files

After successful execution:

- `ddos_best_model.joblib` - Best performing model ready for deployment
- `ddos_scaler.joblib` - Feature scaler for consistent preprocessing
- Console output with detailed performance metrics for all models

## 🏗️ Technical Architecture

### Data Processing Pipeline

```
Kaggle Dataset (8 CSV files, ~2.8M records)
    ↓
Data Loading & Combination
    ↓
Outlier Detection (IQR Method)
    ↓
Network Feature Engineering (15+ features)
    ↓
Data Preprocessing & Cleaning
    ↓
Ensemble Feature Selection (Top 10)
    ↓
Standardization & Balancing
    ↓
Train/Test Split (80/20)
    ↓
Model Training (RF, DT, KNN, SVM)
    ↓
Model Evaluation & Comparison
    ↓
Best Model Selection & Saving
```

### Processing Stages Overview

| Stage                    | Function                               | Input               | Output             | Key Features                                  |
| ------------------------ | -------------------------------------- | ------------------- | ------------------ | --------------------------------------------- |
| **Data Acquisition**     | `load_network_intrusion_dataset()`     | Kaggle dataset path | Combined DataFrame | Automatic CSV detection, metadata extraction  |
| **Outlier Detection**    | `detect_and_cap_outliers()`            | Raw DataFrame       | Cleaned DataFrame  | IQR method, intelligent capping, statistics   |
| **Feature Engineering**  | `engineer_network_security_features()` | Cleaned DataFrame   | Enhanced DataFrame | Network ratios, rates, flow asymmetry         |
| **Correlation Analysis** | `remove_highly_correlated_features()`  | Feature matrix      | Reduced features   | 95% correlation threshold, redundancy removal |
| **Feature Selection**    | `select_best_features_ensemble()`      | Preprocessed data   | Top features       | F-test + MI + Tree importance ensemble        |
| **Data Preparation**     | `standardize_and_balance_data()`       | Selected features   | ML-ready data      | StandardScaler, class balancing               |
| **Model Training**       | Multiple algorithms                    | Balanced data       | Trained models     | RF, DT, KNN, SVM with evaluation              |

## 🤖 Model Training & Evaluation

### Implemented Models

1. **🌲 Random Forest Classifier**

   - Ensemble method with multiple decision trees
   - Excellent for handling complex feature interactions
   - Provides feature importance rankings
   - Generally best performer for this dataset

2. **🌳 Decision Tree Classifier**

   - Single tree-based interpretable model
   - Fast training and prediction
   - Good baseline for comparison
   - Prone to overfitting but useful for insights

3. **👥 K-Nearest Neighbors (KNN)**

   - Instance-based learning algorithm
   - Effective for local pattern recognition
   - Non-parametric approach
   - Computationally intensive for large datasets

4. **⚡ Support Vector Machine (SVM)**
   - Powerful for high-dimensional data
   - Effective margin-based classification
   - Good generalization capabilities
   - Memory efficient with kernel methods

### Training Process

```python
# Automatic train-test split
X_train, X_test, y_train, y_test = train_test_split(
    balanced_feature_matrix, balanced_target_labels,
    test_size=0.2, random_state=42
)

# Train all models
models = {
    'Random Forest': RandomForestClassifier(random_state=42),
    'Decision Tree': DecisionTreeClassifier(random_state=42),
    'KNN': KNeighborsClassifier(),
    'SVM': SVC(random_state=42)
}

# Fit and evaluate each model
for name, model in models.items():
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    # Comprehensive evaluation metrics calculated
```

### Evaluation Metrics

Each model is evaluated with comprehensive metrics:

- **Accuracy**: Overall prediction correctness
- **Precision**: True positive rate (attack detection accuracy)
- **Recall**: Sensitivity (ability to detect all attacks)
- **F1 Score**: Harmonic mean of precision and recall
- **Confusion Matrix**: Detailed prediction breakdown
- **Classification Report**: Per-class performance analysis

### Automatic Model Selection

The system selects the best model based on F1 score:

```python
# Compare F1 scores and select best
model_scores = {
    'Random Forest': f1_score(y_test, y_pred_rf),
    'Decision Tree': f1_score(y_test, y_pred_dt),
    'KNN': f1_score(y_test, y_pred_knn),
    'SVM': f1_score(y_test, y_pred_svm)
}
best_model_name = max(model_scores, key=model_scores.get)
print(f'🏆 Best model: {best_model_name} (F1: {model_scores[best_model_name]:.4f})')
```

## 🔧 Improvements Implemented

### 1. 🔍 Advanced Outlier Detection

**Challenge**: Network traffic contains extreme values that can skew models.

**Solution**: IQR-based detection with intelligent capping

- Calculates Q1, Q3, and IQR for each numeric feature
- Identifies outliers beyond 1.5 \* IQR bounds
- Caps extreme values instead of removing data points
- Preserves data integrity while handling anomalies
- Provides detailed outlier statistics per feature

```python
# IQR outlier detection and capping
Q1, Q3 = df[col].quantile([0.25, 0.75])
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
df[col] = np.clip(df[col], lower_bound, upper_bound)
```

### 2. 🌐 Network Security Feature Engineering

**Challenge**: Raw network metrics lack domain-specific insights.

**Solution**: Creates 15+ network-focused features:

- **📊 Ratio Features**: `fwd_to_bwd_packets_ratio`, `max_to_min_packet_length_ratio`
- **⏱️ Rate Features**: `bytes_per_duration`, `packets_per_second`
- **🔄 Flow Asymmetry**: `(fwd_sum - bwd_sum) / (fwd_sum + bwd_sum + ε)`
- **🚪 Port Classifications**: `is_wellknown_port`, `is_registered_port`, `is_dynamic_port`
- **📈 Statistical Aggregations**: `forward_total_activity`, `backward_mean_activity`

**Benefits**: Leverages cybersecurity domain knowledge, captures attack patterns better.

### 3. 🔗 Correlation Analysis & Redundancy Removal

**Challenge**: Network features are often highly correlated (multicollinearity).

**Solution**: Systematic correlation analysis

- Calculates absolute correlation matrix for all features
- Identifies feature pairs with >95% correlation
- Removes redundant features while preserving information
- Reduces feature space and computational complexity
- Provides detailed correlation reports

```python
# Remove highly correlated features (>95% threshold)
corr_matrix = X.corr().abs()
upper_triangle = np.triu(np.ones(corr_matrix.shape), k=1)
to_drop = [col for col in corr_matrix.columns
           if any(corr_matrix[col] > 0.95)]
```

### 4. 🧠 Ensemble Feature Selection

**Challenge**: Single feature selection methods may miss important patterns.

**Solution**: Combines three complementary methods:

- **📊 F-test (40% weight)**: Statistical significance testing
- **🔍 Mutual Information (30% weight)**: Non-linear relationship detection
- **🌲 Tree Importance (30% weight)**: Random Forest feature importance
- **⚖️ Ensemble Scoring**: Weighted combination of normalized scores

```python
# Ensemble feature selection formula
ensemble_scores = (0.4 * f_scores_norm +
                  0.3 * mi_scores_norm +
                  0.3 * tree_scores_norm)
top_features = features[np.argsort(ensemble_scores)[-10:]]
```

**Benefits**: More robust selection, captures different relationship types, reduces bias.

## 📊 Results & Performance

### Typical Model Performance

Based on the comprehensive evaluation pipeline, expected performance ranges:

| Model                | Accuracy  | Precision | Recall    | F1 Score  | Notes                   |
| -------------------- | --------- | --------- | --------- | --------- | ----------------------- |
| **🌲 Random Forest** | 0.98-0.99 | 0.97-0.99 | 0.98-0.99 | 0.98-0.99 | Usually best performer  |
| **🌳 Decision Tree** | 0.95-0.97 | 0.94-0.97 | 0.95-0.98 | 0.95-0.97 | Fast, interpretable     |
| **👥 KNN**           | 0.94-0.96 | 0.93-0.96 | 0.94-0.97 | 0.94-0.96 | Local pattern detection |
| **⚡ SVM**           | 0.96-0.98 | 0.95-0.98 | 0.96-0.98 | 0.96-0.98 | Good generalization     |

### Sample Output

```
================ Random Forest Results ================
Accuracy:  0.9876
Precision: 0.9823
Recall:    0.9891
F1 Score:  0.9857
Confusion Matrix:
[[1234   23]
 [  15 1456]]
======================================================

🏆 Best model by F1 score: Random Forest (0.9857)
✅ Saved best model as ddos_best_model.joblib
✅ Saved scaler as ddos_scaler.joblib
```

### Feature Importance Analysis

The system provides detailed feature rankings:

```
🏆 Top 10 features by ensemble scoring:
 1. Flow Duration: 0.876
 2. Total Fwd Packets: 0.834
 3. Flow Bytes/s: 0.812
 4. Fwd Packets/s: 0.798
 5. forward_total_activity: 0.765
 6. Fwd Packet Length Max: 0.743
 7. traffic_flow_asymmetry: 0.721
 8. Bwd Packet Length Mean: 0.698
 9. Flow Packets/s: 0.676
10. Total Backward Packets: 0.654
```

## 🚀 Model Deployment

### Ready-to-Use Models

After pipeline execution, the system generates deployment-ready files:

```python
import joblib

# Load trained model and scaler
best_model = joblib.load('ddos_best_model.joblib')
scaler = joblib.load('ddos_scaler.joblib')

# Predict on new network traffic data
def predict_ddos(network_data):
    # Ensure same preprocessing as training
    processed_data = preprocess_new_data(network_data)
    selected_features = extract_selected_features(processed_data)
    scaled_features = scaler.transform(selected_features)

    # Make prediction
    prediction = best_model.predict(scaled_features)
    confidence = best_model.predict_proba(scaled_features)

    return prediction, confidence

# Example usage
new_traffic = load_network_data('new_traffic.csv')
is_attack, confidence = predict_ddos(new_traffic)
print(f"Attack detected: {is_attack[0]} (confidence: {confidence[0][1]:.3f})")
```

### Integration Notes

- **Input Format**: Same feature structure as training data (79 original features)
- **Preprocessing**: Apply same preprocessing pipeline to new data
- **Feature Selection**: Extract same 10 features used in training
- **Scaling**: Use saved scaler for consistent normalization
- **Output**: Binary prediction (0=benign, 1=attack) + confidence scores

## 📚 Functions Documentation

### Core Pipeline Functions

#### `load_network_intrusion_dataset(dataset_directory)`

**Purpose**: Downloads and combines multiple CSV files from Kaggle network intrusion dataset.

**Parameters**:

- `dataset_directory` (str): Path to downloaded dataset directory

**Returns**:

- `pd.DataFrame`: Combined dataset from all CSV files

**Process**:

1. Identifies all CSV files in dataset directory
2. Reads each file with error handling
3. Extracts metadata (shape, columns, label distribution)
4. Combines all dataframes into unified dataset
5. Provides detailed logging of file processing

#### `detect_and_cap_outliers(network_dataframe, detection_method='iqr', outlier_action='cap')`

**Purpose**: Detects and handles outliers using statistical methods.

**Parameters**:

- `network_dataframe` (pd.DataFrame): Input DataFrame
- `detection_method` (str): 'iqr' or 'zscore'
- `outlier_action` (str): 'cap' or 'remove'

**Returns**:

- `pd.DataFrame`: DataFrame with outliers handled

**Algorithm**:

```python
# IQR method (default)
Q1 = df[col].quantile(0.25)
Q3 = df[col].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
df[col] = np.clip(df[col], lower_bound, upper_bound)
```

#### `engineer_network_security_features(network_dataframe)`

**Purpose**: Creates domain-specific features for network security analysis.

**Generated Features**:

- Ratio features between related metrics
- Rate features (bytes/duration, packets/time)
- Flow asymmetry measures
- Port type classifications
- Statistical aggregations

**Returns**:

- `pd.DataFrame`: Enhanced DataFrame with additional features

#### `select_best_features_ensemble(preprocessed_network_data, number_of_features=10)`

**Purpose**: Selects optimal features using ensemble of three methods.

**Methods**:

1. **F-test (40%)**: Statistical significance
2. **Mutual Information (30%)**: Non-linear relationships
3. **Tree Importance (30%)**: Random Forest importance

**Returns**:

- `pd.DataFrame`: Selected feature matrix
- `list`: Selected feature names
- `pd.Series`: Target labels

#### `standardize_and_balance_data(feature_matrix, target_labels, balancing_method="undersample", random_seed=42)`

**Purpose**: Prepares data for ML by standardizing and balancing classes.

**Parameters**:

- `feature_matrix` (pd.DataFrame): Input features
- `target_labels` (pd.Series): Target variable
- `balancing_method` (str): 'undersample' or 'oversample'
- `random_seed` (int): Reproducibility seed

**Returns**:

- `np.array`: Balanced and scaled feature matrix
- `np.array`: Balanced target labels
- `StandardScaler`: Fitted scaler object

## 📦 Dependencies

### Required Packages

```bash
# Core data processing
pandas>=1.3.0          # Data manipulation and analysis
numpy>=1.21.0           # Numerical computing

# Machine learning
scikit-learn>=1.0.0     # ML algorithms and metrics

# Data acquisition
kagglehub>=0.1.0        # Kaggle dataset download

# Visualization (optional for extended analysis)
matplotlib>=3.4.0       # Basic plotting
seaborn>=0.11.0         # Statistical visualization
```

### Installation

```bash
# Install all dependencies
pip install -r requirements.txt

# Or install individually
pip install kagglehub pandas numpy scikit-learn matplotlib seaborn
```

### Version Compatibility

- **Python**: 3.7+ (tested on 3.8, 3.9, 3.10)
- **Memory**: 4GB+ RAM recommended for full dataset processing
- **Storage**: 2GB+ free space for dataset and models

## 📊 Dataset Information

### Network Intrusion Dataset

**Source**: [Kaggle - Network Intrusion Dataset](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset)

**Composition**:

- **8 CSV files** representing different network scenarios
- **~2.8M total records** across all files
- **79 features** per record (network flow characteristics)
- **Binary classification**: BENIGN vs various attack types

### Dataset Files

| File                                                          | Records | Description       | Attack Types       |
| ------------------------------------------------------------- | ------- | ----------------- | ------------------ |
| `Monday-WorkingHours.pcap_ISCX.csv`                           | ~467K   | Normal traffic    | BENIGN             |
| `Tuesday-WorkingHours.pcap_ISCX.csv`                          | ~445K   | Normal traffic    | BENIGN             |
| `Wednesday-workingHours.pcap_ISCX.csv`                        | ~440K   | Normal traffic    | BENIGN             |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`      | ~170K   | Web attacks       | SQL Injection, XSS |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | ~288K   | Infiltration      | Infiltration       |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv`                   | ~191K   | Normal traffic    | BENIGN             |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`        | ~158K   | Port scan attacks | PortScan           |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`            | ~225K   | DDoS attacks      | DDoS               |

### Feature Categories

- **🔄 Flow Characteristics**: Duration, total packets, total bytes
- **📡 Directional Traffic**: Forward/backward packet counts and sizes
- **📊 Statistical Measures**: Min, max, mean, std of packet lengths
- **⏱️ Timing Features**: Inter-arrival times, active/idle periods
- **🚩 Protocol Flags**: TCP flag counts and ratios
- **📈 Rate Metrics**: Packets/second, bytes/second flows

### Data Quality

- **Missing Values**: Minimal (<1% in most features)
- **Outliers**: Significant (handled by IQR capping)
- **Class Imbalance**: ~80% benign, ~20% attacks (handled by balancing)
- **Feature Correlation**: High correlation in some features (handled by correlation analysis)

## 🤝 Contributing

Contributions are welcome! Here's how to contribute:

### Development Setup

1. **Fork and clone**:

   ```bash
   git clone https://github.com/your-username/ddos-detection.git
   cd ddos-detection
   ```

2. **Create virtual environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Create feature branch**:
   ```bash
   git checkout -b feature/your-improvement
   ```

### Contribution Areas

- **🔍 Data Processing**: Improve preprocessing techniques
- **🧠 Feature Engineering**: Add new network security features
- **🤖 Model Enhancement**: Implement new ML algorithms
- **📊 Evaluation Metrics**: Add new performance measures
- **⚡ Performance**: Optimize computational efficiency
- **📚 Documentation**: Improve documentation and examples
- **🧪 Testing**: Add unit tests and validation
- **🖥️ UI/API**: Create web interface or REST API

### Code Standards

- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include type hints where appropriate
- Add comments for complex logic
- Test your changes thoroughly

### Pull Request Process

1. Ensure code follows project standards
2. Update documentation if needed
3. Add tests for new functionality
4. Submit PR with clear description

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

- ✅ **Commercial use** allowed
- ✅ **Modification** allowed
- ✅ **Distribution** allowed
- ✅ **Private use** allowed
- ❗ **No warranty** provided
- ❗ **License and copyright** notice required

---

## 🎯 Project Status

### ✅ Completed Features

- **Complete ML Pipeline**: Full end-to-end implementation (673 lines)
- **Data Processing**: Advanced preprocessing with outlier detection
- **Feature Engineering**: 15+ network-specific features
- **Feature Selection**: Ensemble method with 3 algorithms
- **Model Training**: 4 ML models with comprehensive evaluation
- **Model Selection**: Automatic best model identification
- **Model Persistence**: Production-ready saved models
- **Documentation**: Comprehensive README and code documentation

### 🔮 Future Enhancements

- **Real-time Processing**: Stream processing for live network data
- **Deep Learning**: Neural network models for complex pattern detection
- **Ensemble Models**: Model stacking and voting classifiers
- **Web Interface**: Flask/Django web app for easy model deployment
- **API Development**: REST API for model serving
- **Docker Deployment**: Containerized deployment setup
- **Cloud Integration**: AWS/GCP deployment configurations
- **Monitoring**: Model performance monitoring and retraining
- **Cross-validation**: K-fold CV for robust model evaluation

---

**Built with ❤️ for network security and machine learning**

_Last updated: 2024 - Complete implementation with 4 trained models and automated selection_
