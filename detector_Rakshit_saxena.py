import pandas as pd
import json
import re
import argparse
from typing import Dict, Any, Tuple

class PIIDetectorRedactor:
    def __init__(self):
        # Patterns for detecting PII
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]{1}\d{7}\b')
        self.upi_pattern = re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w+\b|\b\d{10}@\w+\b')
        
        self.combinatorial_pii_fields = ['name', 'email', 'address', 'device_id', 'ip_address']
        
    def detect_pii(self, data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        redacted_data = data.copy()
        standalone_pii_found = False
        combinatorial_pii_count = 0
        combinatorial_fields_found = []
        
        for key, value in data.items():
            if isinstance(value, str):
                # Check standalone PII
                if key == 'phone' and self.phone_pattern.search(value):
                    standalone_pii_found = True
                    redacted_data[key] = self.redact_phone(value)
                elif key == 'aadhar' and self.aadhar_pattern.search(value):
                    standalone_pii_found = True
                    redacted_data[key] = self.redact_aadhar(value)
                elif key == 'passport' and self.passport_pattern.search(value):
                    standalone_pii_found = True
                    redacted_data[key] = self.redact_passport(value)
                elif key == 'upi_id' and self.upi_pattern.search(value):
                    standalone_pii_found = True
                    redacted_data[key] = self.redact_upi(value)
                
                # Check combinatorial PII
                if key in self.combinatorial_pii_fields:
                    combinatorial_pii_count += 1
                    combinatorial_fields_found.append(key)
        
        combinatorial_pii_found = combinatorial_pii_count >= 2
        
        if combinatorial_pii_found:
            for field in combinatorial_fields_found:
                if field == 'name' and 'name' in redacted_data:
                    redacted_data['name'] = self.redact_name(redacted_data['name'])
                elif field == 'email' and 'email' in redacted_data:
                    redacted_data['email'] = self.redact_email(redacted_data['email'])
                elif field == 'address' and 'address' in redacted_data:
                    redacted_data['address'] = '[REDACTED_ADDRESS]'
                elif field == 'device_id' and 'device_id' in redacted_data:
                    redacted_data['device_id'] = '[REDACTED_DEVICE_ID]'
                elif field == 'ip_address' and 'ip_address' in redacted_data:
                    redacted_data['ip_address'] = '[REDACTED_IP]'
        
        is_pii = standalone_pii_found or combinatorial_pii_found
        return is_pii, redacted_data
    
    def redact_phone(self, phone: str) -> str:
        return phone[:2] + 'XXXXXX' + phone[-2:]
    
    def redact_aadhar(self, aadhar: str) -> str:
        return aadhar[:4] + 'XXXX' + aadhar[-4:]
    
    def redact_passport(self, passport: str) -> str:
        return passport[0] + 'XXXXXXX'
    
    def redact_upi(self, upi: str) -> str:
        if '@' in upi:
            parts = upi.split('@')
            return parts[0][:2] + 'XXX@' + parts[1]
        return 'XXX@XXX'
    
    def redact_name(self, name: str) -> str:
        parts = name.split()
        if len(parts) >= 2:
            return parts[0][0] + 'XXX ' + parts[-1][0] + 'XXX'
        return name[0] + 'XXX'
    
    def redact_email(self, email: str) -> str:
        parts = email.split('@')
        return parts[0][:2] + 'XXX@' + parts[1]

def process_csv(input_file: str, output_file: str):
    df = pd.read_csv(input_file)
    detector = PIIDetectorRedactor()
    
    redacted_data_list = []
    is_pii_list = []
    
    for index, row in df.iterrows():
        try:
            data_json = json.loads(row['data_json'].replace("'", '"'))
            is_pii, redacted_data = detector.detect_pii(data_json)
            redacted_data_list.append(json.dumps(redacted_data))
            is_pii_list.append(is_pii)
        except:
            redacted_data_list.append(row['data_json'])
            is_pii_list.append(False)
    
    output_df = pd.DataFrame({
        'record_id': df['record_id'],
        'redacted_data_json': redacted_data_list,
        'is_pii': is_pii_list
    })
    
    output_df.to_csv(output_file, index=False)
    print(f"Output saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='PII Detector and Redactor')
    parser.add_argument('input_file', help='Input CSV file path')
    args = parser.parse_args()
    
    output_file = "redacted_output.csv"
    process_csv(args.input_file, output_file)