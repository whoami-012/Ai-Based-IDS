import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Load NSL-KDD dataset
data = pd.read_csv('KDDTest+.txt', header=None)

# Assign column names
columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
           "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
           "num_compromised", "root_shell", "su_attempted", "num_root",
           "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
           "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
           "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
           "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
           "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
           "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
           "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"]

data.columns = columns

# Drop 'difficulty_level'
data = data.drop(columns=['difficulty_level'])

# Convert labels to binary
data['label'] = data['label'].apply(lambda x: 'attack' if x != 'normal' else 'normal')

# One-hot encode categorical features
data = pd.get_dummies(data, columns=['protocol_type', 'service', 'flag'])

# Normalize numerical features
scaler = StandardScaler()
X = scaler.fit_transform(data.drop('label', axis=1))

# Save preprocessed data
X = pd.DataFrame(X, columns=data.drop('label', axis=1).columns)
y = pd.DataFrame(data['label'], columns=['label'])
preprocessed_data = pd.concat([X, y], axis=1)
preprocessed_data.to_csv('preprocessed_data.csv', index=False)
