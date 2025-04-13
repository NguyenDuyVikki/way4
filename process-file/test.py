import os
import time
from datetime import datetime

def create_test_xml_files(folder_path: str, num_files: int = 3, delay: float = 0.5):
    os.makedirs(folder_path, exist_ok=True)

    print(f"[{datetime.now()}] Creating {num_files} XML test files in '{folder_path}'...\n")

    for i in range(num_files):
        timestamp = int(time.time())
        file_name = f"test_file_{timestamp}_{i}.xml"
        file_path = os.path.join(folder_path, file_name)
        
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<note>
    <to>User</to>
    <from>Generator</from>
    <heading>Test XML {i}</heading>
    <body>This is a test XML file created at {datetime.now()}</body>
</note>
"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(xml_content)

        print(f"✔ Created: {file_path}")
        time.sleep(delay)  # Tạo khoảng cách thời gian giữa các file để khác mtime

    print("\n✅ Done creating test XML files.")

if __name__ == "__main__":
    folder = "/Users/duynguyen/Documents/vikki-bank/de-training/vikki-train/way4/process-file/file_test/demo/demo1"
    create_test_xml_files(folder_path=folder, num_files=5, delay=1)
