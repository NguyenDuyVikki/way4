import os
from datetime import datetime
import io
from typing import List, Tuple
import re
import hashlib
from xml.dom import minidom
from io import BytesIO
from enum import Enum
import gnupg
import sys
import yaml
from pathlib import Path

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

def format_logging_message(department, file_name, status, event_type, details):
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S") + f".{int(now.microsecond / 1000):03d}"
    return (
        f"[{timestamp}] "
        f"[Dept: {department}] "
        f" Processing [File: {file_name}] "
        f"[Status: {status}] "
        f"[Event: {event_type}] "
        f"[Details: {details}]"
    )

def write_logging_to_file(file_path, message):
    try:
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(message + '\n')
    except Exception as e:
        print(f"Error writing to log file: {e}")

def log_event(log_file, department, file_name, status, event_type, details=""):
    message = format_logging_message(
        department=department,
        file_name=file_name,
        status=status,
        event_type=event_type,
        details=details
    )
    write_logging_to_file(log_file, message)

def check_summary_file(file_path, log_file, department):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            log_event(log_file, department, file_path, LogStatus.SUCCESS,
                     LogEvent.PROCESSING, "Successfully read summary file")
            return bool(content)
    except Exception as e:
        log_event(log_file, department, file_path, LogStatus.ERROR,
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

def verify_checksum(file_path, expected_checksum, log_file, department):
    try:
        actual_checksum = calculate_checksum(file_path)
        if actual_checksum is None:
            return False
        result = actual_checksum == expected_checksum.lower()
        log_event(log_file, department, file_path,
                 LogStatus.SUCCESS if result else LogStatus.FAILED,
                 LogEvent.VERIFY, f"Checksum verification: {result}")
        return result
    except Exception as e:
        log_event(log_file, department, file_path, LogStatus.ERROR,
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
                       department: str = None) -> List[Tuple[str, float, str]]:
    file_info = []
    try:
        for item_name in os.listdir(folder_path):
            item_path = os.path.join(folder_path, item_name)
            if os.path.isdir(item_path):
                file_info.extend(
                    list_files_recursive(item_path, file_types, regex_pattern,
                                      log_file, department)
                )
                continue
            if os.path.isfile(item_path):
                mtime = os.path.getmtime(item_path)
                if (not file_types or any(item_name.endswith(ext) for ext in file_types)) and \
                   (not regex_pattern or re.match(regex_pattern, item_name)):
                    checksum = calculate_checksum(item_path)
                    if checksum:
                        file_info.append((item_path, mtime, checksum))
        log_event(log_file, department, folder_path, LogStatus.SUCCESS,
                 LogEvent.FILE_SCAN, f"Found {len(file_info)} matching files")
    except Exception as e:
        log_event(log_file, department, folder_path, LogStatus.ERROR,
                 LogEvent.FILE_SCAN, f"Error listing files: {str(e)}")
        raise RuntimeError(f"An error occurred while listing files in {folder_path}: {e}")
    return file_info

def filter_newest_file_with_checkpoint(
    log_file_path: str,
    folder_path: str,
    checkpoint_file: str,
    file_types: List[str] = None,
    regex_pattern: str = None,
    log_file: str = None,
    department: str = None
) -> List[Tuple[str, float, str]]:
    if not os.path.exists(folder_path):
        log_event(log_file, department, folder_path, LogStatus.ERROR,
                 LogEvent.FILE_SCAN, "Folder not found")
        raise RuntimeError("Folder not found.")

    files = list_files_recursive(folder_path, file_types, regex_pattern,
                               log_file, department)
    if not files:
        log_event(log_file, department, folder_path, LogStatus.FAILED,
                 LogEvent.FILE_SCAN, "No matching files found")
        raise RuntimeError("No matching files found.")

    last_mtime = 0.0
    last_checksum = None
    try:
        if os.path.exists(checkpoint_file):
            with open(checkpoint_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        last_mtime_str, last_file, last_checksum = last_line.split("|", 2)
                        last_mtime = float(last_mtime_str)
    except Exception as e:
        log_event(log_file, department, checkpoint_file, LogStatus.ERROR,
                 LogEvent.CHECKPOINT, f"Error reading checkpoint: {str(e)}")

    new_files = [
        (path, mtime, checksum)
        for path, mtime, checksum in files
        if mtime > last_mtime or (mtime == last_mtime and checksum != last_checksum)
    ]

    for path, mtime, checksum in new_files:
        log_event(
            log_file_path,
            department,
            path,
            LogStatus.SELECTED,
            LogEvent.FILE_SCAN,
            f"Selected file with mtime: {mtime}, checksum: {checksum}"
        )
    if not new_files:
        log_event(log_file, department, folder_path, LogStatus.FAILED,
                 LogEvent.FILE_SCAN, "No new files detected")
        raise RuntimeError("No new files detected.")

    new_files.sort(key=lambda x: x[1], reverse=True)

    return new_files


def get_gpg_binary_path():
    if getattr(sys, 'frozen', False):  # Running as .exe
        base_path = sys._MEIPASS
        gpg_path = os.path.join(base_path, 'gnupg', 'bin', 'gpg.exe')
    else:
        gpg_path = None  # Let gnupg find system GPG when not bundled
    return gpg_path

def encrypt_file(xml_files: list, key: str, dir_path, log_file_tpath) -> bool:
    try:
        # Use bundled GPG binary
        gpg_binary = get_gpg_binary_path()
        gpg = gnupg.GPG(gpgbinary=gpg_binary, gnupghome=None)
        import_result = gpg.import_keys(key)
        if import_result.count == 0:
            log_event(log_file_path, "N/A", LogStatus.ERROR,
                     LogEvent.FILE_ENCRYPT, "GPG key import failed")
            raise ValueError("GPG key import failed")
        fingerprints = [key["fingerprint"] for key in import_result.results]
        gpg.trust_keys(fingerprints, 'TRUST_ULTIMATE')

        success = True
        for file_key in xml_files:
            if not file_key or not os.path.exists(file_key):
                log_event(log_file_path, file_key or "N/A", LogStatus.ERROR,
                         LogEvent.FILE_ENCRYPT, "File not found or invalid")
                success = False
                continue
            print(f"Processing file: {file_key}")
            try:
                base_filename = os.path.splitext(os.path.basename(file_key))[0]
                output_filename = os.path.join(dir_path, f"{base_filename}.gpg")
                with open(file_key, 'rb') as f:
                    file_content = io.BytesIO(f.read())
                file_content.seek(0)

                encrypted_data = gpg.encrypt(
                    file_content.getvalue(),
                    fingerprints,
                    always_trust=True
                )
                file_content.close()

                if not encrypted_data.ok:
                    log_event(log_file_path, file_key, LogStatus.ERROR,
                             LogEvent.FILE_ENCRYPT, f"Encryption failed: {encrypted_data.stderr}")
                    success = False
                    continue
                with open(output_filename, 'w', encoding='utf-8') as f:
                    f.write(str(encrypted_data))
                log_event(log_file_path, file_key, LogStatus.ENCRYPTED,
                         LogEvent.FILE_ENCRYPT, "File encrypted successfully")
            except Exception as e:
                log_event(log_file_path, file_key, LogStatus.ERROR,
                         LogEvent.FILE_ENCRYPT, f"Encryption error: {str(e)}")
                success = False
                continue

        return success

    except Exception as e:
        log_event(log_file_path, "N/A", LogStatus.ERROR,
                 LogEvent.FILE_ENCRYPT, f"Encryption process error: {str(e)}")
        raise

def update_checkpoint_file(log_file, department, checkpoint_file: str, newest_file: str, newest_mtime: float, newest_checksum: str):
    try:
        with open(checkpoint_file, 'a', encoding='utf-8') as f:
            f.write(f"{newest_mtime}|{newest_file}|{newest_checksum}\n")
        log_event(log_file, department, newest_file, LogStatus.SUCCESS,
                 LogEvent.CHECKPOINT, f"Updated checkpoint for file: {newest_file}")
    except Exception as e:
        log_event(log_file, department, checkpoint_file, LogStatus.ERROR,
                 LogEvent.CHECKPOINT, f"Error updating checkpoint: {str(e)}")

def load_config(config_path=None):
    """Load configuration from a YAML file. Default: same folder as the executable."""
    try:
        if config_path is None:
            exe_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent
            config_path = exe_dir / 'config.yml'
        else:
            config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found at {config_path}")

        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)

        if config is None:
            raise ValueError("Config file is empty")

        required_keys = ['input_folder', 'output_folder', 'file_types', 'gpg_key', 'checkpoint_file', 'log_file']
        missing_keys = [key for key in required_keys if key not in config]
        if missing_keys:
            raise ValueError(f"Config file missing required keys: {missing_keys}")

        # Convert paths to absolute to avoid issues on Windows
        config['input_folder'] = str(Path(config['input_folder']).resolve())
        config['output_folder'] = str(Path(config['output_folder']).resolve())
        config['gpg_key'] = str(Path(config['gpg_key']).resolve())
        config['checkpoint_file'] = str(Path(config['checkpoint_file']).resolve())
        config['log_file'] = str(Path(config['log_file']).resolve())

        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        raise

def main():
    department = "Processing"
    try:
        config = load_config()
        xml_dir = config['input_folder']
        file_types = config['file_types']
        gpg_key_path = config['gpg_key']
        checkpoint_file_path = config['checkpoint_file']
        log_file_path = config['log_file']
        dir_encrypt_path = config['output_folder']

        # Ensure directories exist
        os.makedirs(dir_encrypt_path, exist_ok=True)
        os.makedirs(xml_dir, exist_ok=True)
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        os.makedirs(os.path.dirname(checkpoint_file_path), exist_ok=True)

        log_event(log_file_path, department, "", LogStatus.STARTED,
                 LogEvent.PROCESS_START, "Initiating file processing")

        new_files = filter_newest_file_with_checkpoint(
            log_file_path, xml_dir, checkpoint_file_path, file_types, None,
            log_file_path, department,
        )
        if not new_files:
            log_event(log_file_path, department, xml_dir, LogStatus.FAILED,
                     LogEvent.FILE_SCAN, "No new files detected")
            return

        mc_files = [f for f in [convert_xml_to_mc(file) for file, _, _ in new_files] if f]
        if not mc_files:
            log_event(log_file_path, department, xml_dir, LogStatus.FAILED,
                     LogEvent.PROCESSING, "No valid .mc files generated")
            return

        newest_file, newest_mtime, newest_checksum = new_files[0]
        with open(gpg_key_path, 'r', encoding='utf-8') as key_file:
            gpg_key = key_file.read()

        status = encrypt_file(mc_files, gpg_key, dir_encrypt_path, log_file_path)
        if status:
            log_event(log_file_path, department, newest_file, LogStatus.ENCRYPTED,
                     LogEvent.FILE_ENCRYPT, "All files encrypted successfully")
            update_checkpoint_file(log_file_path, department, checkpoint_file_path,
                                 newest_file, newest_mtime, newest_checksum)
            for file in mc_files:
                if file and os.path.exists(file):
                    try:
                        os.remove(file)
                        log_event(log_file_path, department, file, LogStatus.SUCCESS,
                                 LogEvent.PROCESSING, "Temporary .mc file removed")
                    except Exception as e:
                        log_event(log_file_path, department, file, LogStatus.ERROR,
                                 LogEvent.PROCESSING, f"Failed to remove .mc file: {str(e)}")
        else:
            log_event(log_file_path, department, newest_file, LogStatus.FAILED,
                     LogEvent.FILE_ENCRYPT, "Some files failed to encrypt")

    except Exception as e:
        log_event(log_file_path, department, "", LogStatus.ERROR,
                 LogEvent.PROCESSING, f"Main process error: {str(e)}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()