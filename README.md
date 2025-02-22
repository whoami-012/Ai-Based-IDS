# AI-Based Intrusion Detection System (IDS)

## Overview
The **AI-Based Intrusion Detection System (IDS)** is a cybersecurity tool designed to detect network intrusions using **machine learning**. It analyzes live network traffic and PCAP files to classify packets as **normal** or **attack** based on a trained AI model. The IDS also supports **IP whitelisting** to exclude trusted sources from interference.

This project leverages **Scapy** for packet capture, **Pandas** for data processing, and **Scikit-Learn** for AI-based threat detection. It is an ideal solution for **network security monitoring, penetration testers, and cybersecurity researchers**.

---
## Features
✅ **Live Traffic Monitoring**: Captures and analyzes real-time network traffic.
✅ **PCAP File Analysis**: Reads and processes stored packet captures.
✅ **Machine Learning-Based Detection**: Uses a trained Random Forest model for classification.
✅ **IP Whitelisting**: Excludes specific IPs from interference.
✅ **Intrusion Alerts**: Displays **popup warnings** for detected threats.
✅ **Log File Storage**: Records attack details for later analysis.
✅ **Efficient Performance**: Optimized data processing to handle large traffic volumes.

---
## Technical Details
- **Programming Language**: Python
- **Packet Capture**: Scapy
- **Machine Learning**: Scikit-Learn (RandomForestClassifier)
- **Data Processing**: Pandas, NumPy
- **GUI Alerts**: Tkinter
- **File Handling**: Joblib (model loading), CSV (preprocessing)

The IDS model was trained using network traffic data containing normal and malicious packets. Feature selection focused on **source/destination ports, packet length, protocol type, and traffic behavior.**

---
## Installation & Setup
### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/AI-IDS.git
cd AI-IDS
```

### **2. Install Dependencies**
Ensure Python 3.x is installed, then run:
```bash
pip install -r requirements.txt
```

### **3. Prepare Whitelist (Optional)**
Create a `whitelist.txt` file to add trusted IPs.
```bash
echo "192.168.1.1" >> whitelist.txt
```

### **4. Run the IDS**
#### **Live Traffic Analysis**
```bash
python main.py
```
Select **(1) Live Traffic** to analyze real-time network activity.

#### **PCAP File Analysis**
```bash
python main.py
```
Select **(2) PCAP File**, then enter the file path.

---
## Demo
### **1. Example Detection Output**
```
192.168.1.10:5050 -> 192.168.1.200:80 | Protocol: 6 | Length: 125 | Threat: attack
ALERT: Potential attack from 192.168.1.10 to 192.168.1.200!
```

### **2. Whitelist Behavior**
```
🛑 Skipping whitelisted IP: 192.168.1.1 -> 10.0.0.2
```

---
## Future Improvements
🔹 Enhance model accuracy with deep learning.
🔹 Implement a **dashboard** for real-time traffic visualization.
🔹 Support for **more network protocols**.
🔹 Improve performance for large-scale deployments.

---
## Contributing
Contributions are welcome! Feel free to submit **pull requests** or report **issues**.

---
## License
MIT License - Free to use and modify.

