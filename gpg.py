
    


from xml.dom import minidom
import os
from datetime import datetime

def main():
    folder = "/Users/duynguyen/Documents/vikki-bank/de-training/vikki-train/way4/xml_out/"
    path = folder + "PM_PRS_0001__20250421_000006_LEDB014_NCRD_.xml"
    
    
    try:
        # Parse XML file
        doc = minidom.parse(path)
        
        stt_emv_cr = 1
        text2 = ""
        
        # Get ApplicationDataNotification and Data elements
        parent_nodes = doc.getElementsByTagName("ApplicationDataNotification")
        data_nodes = doc.getElementsByTagName("Data")
        
        for a in range(len(parent_nodes)):
            # Initialize lists for card data
            lst_card_number = []
            lst_from = []
            lst_to = []
            lst_emboss_name = []
            lst_cvc1 = []
            lst_cvc2 = []
            lst_cvc3 = []
            lst_service_code = []
            lst_psn = []
            lst_57 = []
            lst_add2 = []
            lst_company_name = []
            
            # Extract data from Data elements
            for data_node in data_nodes:
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
                elif data_element == "5F34":
                    lst_psn.append(value)
                elif data_element == "57":
                    lst_57.append(value)
                elif data_element == "ADD2":
                    lst_add2.append(value)
            
            # Validate list sizes
            if (len(lst_card_number) < len(parent_nodes) * 2 or
                len(lst_from) < len(parent_nodes) * 2 or
                len(lst_to) < len(parent_nodes) or
                len(lst_emboss_name) < len(parent_nodes) or
                len(lst_cvc1) < len(parent_nodes) or
                len(lst_cvc2) < len(parent_nodes) or
                len(lst_cvc3) < len(parent_nodes) or
                len(lst_service_code) < len(parent_nodes)):
                print(f"Missing value in xml file, please check -- note: list < count card {len(parent_nodes)} = count card")
                return
            
            try:
                # Validate list sizes for specific card
                if not is_valid_list_sizes(a, lst_card_number, lst_from, lst_to, lst_emboss_name,
                                        lst_cvc1, lst_cvc2, lst_cvc3, lst_service_code, lst_psn, lst_57, lst_add2):
                    log_conversion_error(folder, "", f"Insufficient list sizes for card index {a}")
                    print(f"Skipping card at index {a} due to insufficient list sizes")
                    continue
                
                # Extract data for first card type
                str_card_number = lst_card_number[a * 4]
                str_from = lst_from[a * 4]
                str_to = lst_to[a]
                str_emboss_name = lst_emboss_name[a]
                str_cvc1 = lst_cvc1[a]
                str_cvc2 = lst_cvc2[a]
                str_cvc3 = lst_cvc3[a]
                str_service_code = lst_service_code[a * 3]
                str_psn = lst_psn[a * 3]
                str_company_name = ""
                
                # Validate card data
                if not is_valid_card_data(str_card_number, str_from, str_to, str_cvc1, str_cvc2, str_cvc3, str_service_code):
                    log_conversion_error(folder, str_card_number, "Invalid card data for conversion")
                    print(f"Card conversion failed for card number: {str_card_number}")
                    continue
                
                # Build output filename
                filename_mc_cr_emv = os.path.basename(path).replace(".xml", ".mc")
                output_path = os.path.join(folder, filename_mc_cr_emv)
                
                # Build card data for first type
                text2 = build_card_data(text2, stt_emv_cr, str_card_number, str_cvc2, str_from, str_to,
                                      str_emboss_name, str_company_name, str_service_code, str_cvc1, str_cvc3, str_psn)
                
                # MasterCard data
                str_card_number = lst_card_number[a * 4 + 2]
                str_from = lst_from[a * 4 + 2]
                str_to = lst_57[a * 3 + 2][17:21]
                str_emboss_name = lst_emboss_name[a]
                str_cvc1 = lst_57[a * 3 + 2][30:33]
                str_cvc3 = lst_57[a * 3 + 1][30:33]
                
                start_index = lst_add2[a * 3 + 1].find("CVV2=")
                str_cvc2 = lst_add2[a * 3 + 1][start_index + 5:start_index + 8]
                
                str_service_code = lst_service_code[a * 3 + 1]
                str_psn = lst_psn[a * 3 + 1]
                
                # Validate MasterCard data
                if not is_valid_card_data(str_card_number, str_from, str_to, str_cvc1, str_cvc2, str_cvc3, str_service_code):
                    log_conversion_error(folder, str_card_number, "Invalid MasterCard data for conversion")
                    print(f"MasterCard conversion failed for card number: {str_card_number}")
                    continue
                
                # Build card data for MasterCard
                text2 = build_card_data(text2, stt_emv_cr, str_card_number, str_cvc2, str_from, str_to,
                                      str_emboss_name, str_company_name, str_service_code, str_cvc1, str_cvc3, str_psn)
                
                text2 += "\n"
                stt_emv_cr += 1
                
                # Write to file
                with open(output_path, 'w') as f:
                    f.write(text2)
                
                print("Xuat file thanh cong!!")
                
            except IndexError as e:
                log_conversion_error(folder, "", f"IndexError at card index {a}: {str(e)}")
                print(f"Skipping card at index {a} due to IndexError")
                continue
                
    except Exception as e:
        log_conversion_error(folder, "", f"General error: {str(e)}")
        print(f"Error: {str(e)}")

def build_card_data(text2, stt_emv_cr, str_card_number, str_cvc2, str_from, str_to,
                   str_emboss_name, str_company_name, str_service_code, str_cvc1, str_cvc3, str_psn):
    text2 += f"{stt_emv_cr:06d}"  # seq number
    text2 += f"{str_card_number:<16}"  # card_number
    text2 += f"{str_cvc2:<3}"  # CVC2
    text2 += "013481"  # ICA number
    text2 += f"{str_from[2:4]}/{str_from[0:2]}"  # issuance date
    text2 += "    "  # space (4 char)
    text2 += f"{str_to[2:4]}/{str_to[0:2]}"  # expiry date (MM/YY)
    text2 += "M"  # MasterCard symbol
    text2 += f"{'':<26}" if check_no_embossing(str_card_number) == "1" else f"{str_emboss_name:<26}"  # un_nameflag
    text2 += "."  # fix (1 char)
    text2 += f"{str_company_name:<22}"  # company name
    text2 += "    "  # space (4 char)
    text2 += '"'  # magstripe opener
    
    # Track 1
    text2 += "%"  # Track1 start symbol
    text2 += "B"  # track1 Start code
    text2 += f"{str_card_number:<16}"  # card no track1
    text2 += "^"  # t1fs1
    text2 += f"{convert_embossing_name_track1(str_emboss_name):<26}"  # embossing name
    text2 += "^"  # t1fs1
    text2 += f"{str_to[0:2]}{str_to[2:4]}"  # expiry date track1 (YYMM)
    text2 += f"{str_service_code:<3}"  # card type track1 (service code)
    text2 += "1"  # fix 1 char
    text2 += "000000"  # pin offset
    text2 += f"{str_cvc1:<3}"  # CVC1 track1
    text2 += "000000"  # fix 6 char
    text2 += "?"  # track1 end
    text2 += "     "  # 5 space
    
    # Track 2
    text2 += ";"  # track2 start
    text2 += f"{str_card_number:<16}"  # card no track2
    text2 += "="  # Track2 fix
    text2 += f"{str_to[0:2]}{str_to[2:4]}"  # expiry date (YYMM)
    text2 += f"{str_service_code:<3}"  # card type track2 (service code)
    text2 += "00000"  # fix 5 char
    text2 += f"{str_cvc1:<3}"  # CVC1 track2
    text2 += "?"  # track2 end
    
    text2 += "   "  # 3 space
    text2 += ";5f25="  # DT Header
    text2 += f"{str_from[0:2]}{str_from[2:4]}{str_from[4:6]}"  # application effective date (YYMMDD)
    text2 += ";"  # DT Tail
    text2 += f"{str_cvc3:<3}"  # JCB
    text2 += f"{str_psn:<2}"
    text2 += f"{stt_emv_cr:015d}"  # seq BO number
    text2 += ";"
    
    return text2

def is_valid_card_data(card_number, from_date, to_date, cvc1, cvc2, cvc3, service_code):
    if not card_number or len(card_number.strip()) != 16:
        return False
    if not from_date or len(from_date) != 6 or not from_date.isdigit():
        return False
    if not to_date or len(to_date) != 4 or not to_date.isdigit():
        return False
    if not cvc1 or len(cvc1) != 3 or not cvc1.isdigit():
        return False
    if not cvc2 or len(cvc2) != 3 or not cvc2.isdigit():
        return False
    if not cvc3 or len(cvc3) != 3 or not cvc3.isdigit():
        return False
    if not service_code or len(service_code) != 3 or not service_code.isdigit():
        return False
    return True

def is_valid_list_sizes(index, lst_card_number, lst_from, lst_to, lst_emboss_name,
                       lst_cvc1, lst_cvc2, lst_cvc3, lst_service_code, lst_psn, lst_57, lst_add2):
    card_index = index * 4
    card_index_plus_2 = index * 4 + 2
    data_index = index * 3
    data_index_plus_1 = index * 3 + 1
    data_index_plus_2 = index * 3 + 2
    
    return (len(lst_card_number) > card_index_plus_2 and
            len(lst_from) > card_index_plus_2 and
            len(lst_to) > index and
            len(lst_emboss_name) > index and
            len(lst_cvc1) > index and
            len(lst_cvc2) > index and
            len(lst_cvc3) > index and
            len(lst_service_code) > data_index_plus_1 and
            len(lst_psn) > data_index and
            len(lst_57) > data_index_plus_2 and
            len(lst_add2) > data_index_plus_1)

def log_conversion_error(folder, card_number, error_message):
    try:
        with open(os.path.join(folder, "conversion_errors.log"), 'a') as f:
            f.write(f"Error at {datetime.now()} | Card: {card_number} | {error_message}\n")
    except IOError as e:
        print(f"Error writing to log file: {str(e)}")

def check_no_embossing(card_number):
    return "0"

def convert_embossing_name_track1(emboss_name):
    return emboss_name

if __name__ == "__main__":
    main()