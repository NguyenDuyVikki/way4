import time
import os
from datetime import datetime
import io 
from typing import List, Tuple
import re
import hashlib
from xml.dom import minidom
import paramiko
from io import BytesIO
from enum import Enum
import tempfile
import gnupg

PERSO_FILE_PATH = '/Users/duynguyen/Documents/vikki-bank/de-training/vikki-train/way4/process-file/file_test'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

class LogStatus(str, Enum):
    STARTED = "Started"
    SELECTED = "Selected"
    SUCCESS = "Success"
    FAILED = "Failed"
    ERROR = "Error"
    ENCRYPTED = "Encrypted"

class LogEvent(str, Enum):
    PROCESS_START = "ProcessStart"
    FILE_SCAN = "FileScan"
    CHECKSUM = "Checksum"
    VERIFY = "ChecksumVerify"
    CHECKPOINT = "Checkpoint"
    PROCESSING = "Processing"
    FILE_ENCRYPT = "FileEncrypt"
    
def format_logging_message(department, frequency, file_name, status, event_type, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"[{timestamp}] | {department} | {frequency} | {file_name} | {status} | {event_type} | {details}"

def write_logging_to_file(file_path, message):
    try:
        with open(file_path, 'a') as f:
            f.write(message + '\n')
    except Exception as e:
        print(f"Error writing to log file: {e}")

def log_event(log_file, department, frequency, file_name, status, event_type, details=""):
    message = format_logging_message(
        department=department,
        frequency=frequency,
        file_name=file_name,
        status=status,
        event_type=event_type,
        details=details
    )
    write_logging_to_file(log_file, message)

def check_summary_file(file_path, log_file, department, frequency):
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            log_event(log_file, department, frequency, file_path, LogStatus.SUCCESS, 
                     LogEvent.PROCESSING, "Successfully read summary file")
            return bool(content)
    except Exception as e:
        log_event(log_file, department, frequency, file_path, LogStatus.ERROR, 
                 LogEvent.PROCESSING, f"Error reading summary file: {str(e)}")
        return False

def calculate_checksum(file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        checksum = sha256_hash.hexdigest()
        return checksum
    except Exception as e:
        return None

def verify_checksum(file_path, expected_checksum, log_file, department, frequency):
    try:
        actual_checksum = calculate_checksum(file_path, log_file, department, frequency)
        if actual_checksum is None:
            return False
        result = actual_checksum == expected_checksum.lower()
        log_event(log_file, department, frequency, file_path, 
                 LogStatus.SUCCESS if result else LogStatus.FAILED, 
                 LogEvent.VERIFY, f"Checksum verification: {result}")
        return result
    except Exception as e:
        log_event(log_file, department, frequency, file_path, LogStatus.ERROR, 
                 LogEvent.VERIFY, f"Checksum verification failed: {str(e)}")
        return False

def convert_xml_to_mc(xml_file):
    
    try:
        doc = minidom.parse(xml_file)
        doc.normalize()

        data_elements = doc.getElementsByTagName("Data")
        parent_elements = doc.getElementsByTagName("ApplicationDataNotification")

        stt_emv_cr = 1
        
        lst_card_number = []
        lst_from = []
        lst_to = []
        lst_emboss_name = []
        lst_cvc1 = []
        lst_cvc2 = []
        lst_cvc3 = []
        lst_service_code = []
        lst_psn = []
        
        for data_node in data_elements:
            data_element = data_node.getAttribute("DataElement")
            value = data_node.getAttribute("Value")
            
            if data_element == "PAND":
                lst_card_number.append(value)
            elif data_element == "AEDT":
                lst_from.append(value)
            elif data_element == "EXDT":
                lst_to.append(value)
            elif data_element == "CRDN":
                lst_emboss_name.append(value)
            elif data_element == "CVC1":
                lst_cvc1.append(value)
            elif data_element == "CVC2":
                lst_cvc2.append(value)
            elif data_element == "ICVV":
                lst_cvc3.append(value)
            elif data_element == "SVCD":
                lst_service_code.append(value)
                print(f"Service code: {value}")
            elif data_element == "5F34":
                lst_psn.append(value)
        
        parent_length = len(parent_elements)
        print(f"Count card: {parent_length}")
        
        required_sizes = {
            "lst_card_number": parent_length * 2,  # 2 PAND per card
            "lst_from": parent_length,  # Changed to 1 AEDT per card
            "lst_to": parent_length,
            "lst_emboss_name": parent_length,
            "lst_service_code": parent_length
        }
        
        optional_sizes = {
            "lst_cvc1": parent_length,
            "lst_cvc2": parent_length,
            "lst_cvc3": parent_length,
            "lst_psn": parent_length
        }
        
        actual_sizes = {
            "lst_card_number": len(lst_card_number),
            "lst_from": len(lst_from),
            "lst_to": len(lst_to),
            "lst_emboss_name": len(lst_emboss_name),
            "lst_cvc1": len(lst_cvc1),
            "lst_cvc2": len(lst_cvc2),
            "lst_cvc3": len(lst_cvc3),
            "lst_service_code": len(lst_service_code),
            "lst_psn": len(lst_psn)
        }
        
        missing_required = {key: required_sizes[key] - actual_sizes[key] 
                           for key in required_sizes if actual_sizes[key] < required_sizes[key]}
        
        if missing_required:
            print("Missing required values in XML file, please check:")
            for key, count in missing_required.items():
                print(f"- {key}: expected {required_sizes[key]}, got {actual_sizes[key]}, missing {count}")
            return
        
        missing_optional = {key: optional_sizes[key] - actual_sizes[key] 
                           for key in optional_sizes if actual_sizes[key] < optional_sizes[key]}
        if missing_optional:
            print("Warning: Missing optional values in XML file:")
            for key, count in missing_optional.items():
                print(f"- {key}: expected {optional_sizes[key]}, got {actual_sizes[key]}, missing {count}")
        
        for lst in [lst_cvc1, lst_cvc2, lst_cvc3, lst_psn]:
            print(f"Length of {lst}: {len(lst)}")
            while len(lst) < parent_length:
                lst.append("000")
        
        filename_mc_cr_emv = os.path.basename(xml_file).replace(".xml", ".mc")
        output_path = os.path.join(filename_mc_cr_emv)
        with open(output_path, 'w', encoding='utf-8') as f:
            for a in range(parent_length):
                str_card_number = lst_card_number[a * 2]
                str_from = lst_from[a]  # Changed from a * 2 to a
                str_to = lst_to[a]
                str_emboss_name = lst_emboss_name[a]
                str_cvc1 = lst_cvc1[a]
                str_cvc2 = lst_cvc2[a]
                str_cvc3 = lst_cvc3[a]
                str_service_code = lst_service_code[a]
                str_psn = lst_psn[a]
                
                text2 = (
                    f"{stt_emv_cr:06d}" +
                    f"{str_card_number:<16}" +
                    f"{str_cvc2:<3}" +
                    "013481" +
                    f"{str_from[2:4]}/{str_from[0:2]}" +
                    "    " +
                    f"{str_to[2:4]}/{str_to[0:2]}" +
                    "M" +
                    (f"{'':<26}" if check_noembossing(str_card_number) == "1" else f"{str_emboss_name:<26}") +
                    "." +
                    f"{'':<22}" +
                    "    " +
                    '"'
                )
                
                text2 += (
                    "%" +
                    "B" +
                    f"{str_card_number:<16}" +
                    "^" +
                    f"{convert_embossing_name_track1(str_emboss_name):<26}" +
                    "^" +
                    f"{str_to[0:2]}{str_to[2:4]}" +
                    f"{str_service_code:<3}" +
                    "1" +
                    "000000" +
                    f"{str_cvc1:<3}" +
                    "000000" +
                    "?" +
                    "     "
                )
                
                text2 += (
                    ";" +
                    f"{str_card_number:<16}" +
                    "=" +
                    f"{str_to[0:2]}{str_to[2:4]}" +
                    f"{str_service_code:<3}" +
                    "00000" +
                    f"{str_cvc1:<3}" +
                    "?"
                )
                
                text2 += (
                    "   " +
                    ";5f25=" +
                    f"{str_from[0:2]}{str_from[2:4]}{str_from[4:6]}" +
                    ";" +
                    f"{str_cvc3:<3}" +
                    f"{str_psn:<2}" +
                    f"{stt_emv_cr:015d}"
                )
                
                f.write(text2 + "\n")
                stt_emv_cr += 1
        
        print(f"File exported successfully to: {output_path}")
        return output_path
    except FileNotFoundError:
        print(f"Error: Input file not found at {xml_file}")
        return
    except PermissionError:
        print(f"Error: Permission denied when writing to {output_path}")
        return
    except Exception as e:
        print(f"Error: {str(e)}")
        return
         
def check_noembossing(card_number):
    return "0"

def convert_embossing_name_track1(emboss_name):
    return emboss_name

def list_files_recursive(folder_path: str, file_types: List[str] = None, 
                       regex_pattern: str = None, log_file: str = None, 
                       department: str = None, frequency: str = None) -> List[Tuple[str, float, str]]:
    file_info = []
    try:
        for item_name in os.listdir(folder_path):
            item_path = os.path.join(folder_path, item_name)
            if os.path.isdir(item_path):
                file_info.extend(
                    list_files_recursive(item_path, file_types, regex_pattern, 
                                      log_file, department, frequency)
                )
                continue
            if os.path.isfile(item_path):
                mtime = os.path.getmtime(item_path)
                if (not file_types or any(item_name.endswith(ext) for ext in file_types)) and \
                   (not regex_pattern or re.match(regex_pattern, item_name)):
                    checksum = calculate_checksum(item_path) 
                    file_info.append((item_path, mtime, checksum))
        log_event(log_file, department, frequency, folder_path, LogStatus.SUCCESS, 
                 LogEvent.FILE_SCAN, f"Found {len(file_info)} matching files")
    except Exception as e:
        log_event(log_file, department, frequency, folder_path, LogStatus.ERROR, 
                 LogEvent.FILE_SCAN, f"Error listing files: {str(e)}")
        raise RuntimeError(f"An error occurred while listing files in {folder_path}: {e}")
    return file_info


def filter_newest_file_with_checkpoint(
    folder_path: str,
    checkpoint_file: str,
    file_types: List[str] = None,
    regex_pattern: str = None,
    log_file: str = None,
    department: str = None,
    frequency: str = None
) -> List[Tuple[str, float, str]]:
    if not os.path.exists(folder_path):
        log_event(log_file, department, frequency, folder_path, LogStatus.ERROR, 
                 LogEvent.FILE_SCAN, "Folder not found")
        raise RuntimeError("Folder not found.")
    
    files = list_files_recursive(folder_path, file_types, regex_pattern, 
                               log_file, department, frequency)
    if not files:
        log_event(log_file, department, frequency, folder_path, LogStatus.FAILED, 
                 LogEvent.FILE_SCAN, "No matching files found")
        raise RuntimeError("No matching files found.")

    last_mtime = 0.0
    last_checksum = None
    try:
        if os.path.exists(checkpoint_file):
            with open(checkpoint_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        last_mtime_str, last_file, last_checksum = last_line.split("|", 2)
                        last_mtime = float(last_mtime_str)
    except Exception as e:
        log_event(log_file, department, frequency, checkpoint_file, LogStatus.ERROR, 
                 LogEvent.CHECKPOINT, f"Error reading checkpoint: {str(e)}")
    # filter file base on mtime and checksum
    new_files = [(path, mtime, checksum) for path, mtime, checksum in files 
                 if mtime > last_mtime or (mtime == last_mtime and checksum != last_checksum)]
    if not new_files:
        log_event(log_file, department, frequency, folder_path, LogStatus.FAILED, 
                 LogEvent.FILE_SCAN, "No new files detected")
        raise RuntimeError("No new files detected.")

    new_files.sort(key=lambda x: x[1], reverse=True)
    
    try:
        newest_file, newest_mtime, newest_checksum = new_files[0]  
        with open(checkpoint_file, 'a') as f:
            f.write(f"{newest_mtime}|{newest_file}|{newest_checksum}\n")
        log_event(log_file, department, frequency, newest_file, LogStatus.SUCCESS, 
                 LogEvent.CHECKPOINT, f"Updated checkpoint for file: {newest_file}")
    except Exception as e:
        log_event(log_file, department, frequency, checkpoint_file, LogStatus.ERROR, 
                 LogEvent.CHECKPOINT, f"Error updating checkpoint: {str(e)}")
    
    return new_files

def encrypt_file(xml_files: list, key: str, dir_path, log_file_path) -> bool:    
    # Initialize GPG in memory (no gnupghome directory needed)
    gpg = gnupg.GPG()
    
    try:
        # Import key directly from string
        import_result = gpg.import_keys(key)
        if import_result.count == 0:
            raise ValueError("GPG key import failed")
        fingerprints = [key["fingerprint"] for key in import_result.results]
        gpg.trust_keys(fingerprints, 'TRUST_ULTIMATE')
        
        # Process each file
        for file_key in xml_files:
            print(f"Processing file: {file_key}")
            try:
                # Read file content into memory
                          
                base_filename = os.path.splitext(os.path.basename(file_key))[0]
                output_filename = os.path.join(dir_path, f"{base_filename}.gpg")
                with open(file_key, 'rb') as f:
                    file_content = io.BytesIO(f.read())
                file_content.seek(0)
                
                # Encrypt file content
                encrypted_data = gpg.encrypt(
                    file_content.getvalue(),
                    fingerprints,
                    always_trust=True
                )
                file_content.close()  
                
                if not encrypted_data.ok:
                    log_event(log_file_path, file_key, LogStatus.ERROR,
                             LogEvent.FILE_ENCRYPT, f"Encryption failed: {encrypted_data.stderr}")
                    continue
                with open(output_filename, 'w') as f:
                    f.write(str(encrypted_data))
            except Exception as e:
                continue
        
        return True
        
    except Exception as e:
        raise

def main():
    checkpoint_file_path = os.path.join(SCRIPT_DIR, 'checkpoint.txt')
    log_file_path = os.path.join(SCRIPT_DIR, 'processing.log')
    department = "Processing"
    frequency = "Daily"
    folder_path = PERSO_FILE_PATH
    file_types = ['.xml']
    gpg_key_path = os.path.join(SCRIPT_DIR, 'data_4096_pub.asc')  # Assuming a GPG key file
    dir_encrypt_path = os.path.join(SCRIPT_DIR, 'encrypted_files')
    os.makedirs(dir_encrypt_path, exist_ok=True)

    
    try:
        log_event(log_file_path, department, frequency, "", LogStatus.STARTED, 
                 LogEvent.PROCESS_START, "Initiating file processing")
        # check new file
        new_files = filter_newest_file_with_checkpoint(
            folder_path, checkpoint_file_path, file_types, None, 
            log_file_path, department, frequency
        )
        # convert file xml to mc 
        for newest_file, newest_mtime, checksum_file in new_files:
            log_event(log_file_path, department, frequency, newest_file, LogStatus.SELECTED, 
            LogEvent.FILE_SCAN, f"Selected file with mtime: {newest_mtime}, checksum: {checksum_file}") 
            with open(gpg_key_path, 'r') as key_file:
                gpg_key = key_file.read()
            # encrypt file 
            status = encrypt_file([newest_file], gpg_key, dir_encrypt_path, log_file_path)   
            if status:
                log_event(log_file_path, department, frequency, newest_file, LogStatus.ENCRYPTED, 
                         LogEvent.FILE_ENCRYPT, "File encrypted successfully") 

                
        
    except Exception as e:
        log_event(log_file_path, department, frequency, newest_file if 'newest_file' in locals() else "", 
                 LogStatus.ERROR, LogEvent.PROCESSING, f"Main process error: {str(e)}")
        print(f"Error: {e}")


if __name__ == "__main__":
    main()