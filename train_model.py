
from pathlib import Path
import pandas as pd
import joblib
import time

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# 1. Load the dataset
BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "datasets" / "TON_IoT" / "train_test_network.csv"
MODEL_SAVE_PATH = BASE_DIR / "scada_attack_model.joblib"

def train_model():
    print("Loading TON_IoT dataset...")
    df = pd.read_csv(DATA_PATH)

    print("Dataset loaded:", df.shape)

    # 2. Separate input features and target
    # label: 0 = normal, 1 = attack
    # Do not use 'type' as an input because it reveals the attack category.
    y = df["label"].astype(int)

    # Remove target columns and IP addresses to reduce identifier memorization.
    X = df.drop(columns=["label", "type", "src_ip", "dst_ip"])

    # Identify numerical and categorical columns
    numerical_columns = X.select_dtypes(
        include=["number", "bool"]
    ).columns.tolist()

    categorical_columns = X.select_dtypes(
        exclude=["number", "bool"]
    ).columns.tolist()

    print("Numerical features:", len(numerical_columns))
    print("Categorical features:", len(categorical_columns))

    # 3. Prepare the data
    numerical_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    categorical_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(
            handle_unknown="ignore",
            max_categories=30
        ))
    ])

    preprocessor = ColumnTransformer([
        ("num", numerical_pipeline, numerical_columns),
        ("cat", categorical_pipeline, categorical_columns)
    ])

    # 4. Split into training and testing data
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("Training records:", len(X_train))
    print("Testing records:", len(X_test))

    # 5. Create the machine-learning model
    model = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(
            n_estimators=150,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1
        ))
    ])

    # 6. Train the model
    print("\nTraining model. Please wait...")
    start_time = time.time()

    model.fit(X_train, y_train)

    print("Training completed in",
          round(time.time() - start_time, 2), "seconds")

    # 7. Test the model
    print("\nEvaluating model...")
    predictions = model.predict(X_test)

    print("\nAccuracy:",
          round(accuracy_score(y_test, predictions) * 100, 2), "%")

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Attack"],
        zero_division=0
    ))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    # 8. Save the trained model
    joblib.dump(model, MODEL_SAVE_PATH)

    print(f"\nModel saved as {MODEL_SAVE_PATH.name}")
    print("Next, we can integrate it into the dashboard.")
    return model


if __name__ == "__main__":
    train_model()
