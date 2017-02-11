import os,sys
import string
import base64
import fileinput
FIRST_PHASE = "OQTJEqtsK0AUB9YXMwr8idozF7VWRPpnhNCHI6Dlkaubyxf5423jvcZ1LSGmge" 
SECOND_PHASE = "PqOwI1eUrYtT2yR3p4E5o6WiQu7ASlDkFj8GhHaJ9sKdLfMgNzBx0ZcXvCmVnb"
global FULL_KEY
FULL_KEY= ""
def sub_1_for_hex(str_input):
    str_output = ""
    for letter in str_input:
        try:
            str_output += chr(ord(letter)-1)
        except:
            print "sub_1_for_hex func problem"
            continue
    return str_output

def sum_comp_name(comp_name):
    sum = 0
    for letter in comp_name:
        sum+= ord(letter)
    return sum
    
def init_key(comp):    
    comp_name_sum = sum_comp_name(comp)
    carry = divmod(comp_name_sum, 62)
    index = carry[1] -1
    end_key = FIRST_PHASE[:index]
    key = FIRST_PHASE[index:]
    key = key + end_key
    key = key + key
    return key

def decrypt(num_list,offset):
    global FULL_KEY
    input = ""
    for num_str in num_list:
        try:
            input += num_str.decode('hex')
        except:
            input += ')'    
    result = ""
    for i, c in enumerate(input):
        i = i % 62 +1 
        try:
            index = FULL_KEY.index(c)-1
        except ValueError:
            result += c
            continue
        translated = SECOND_PHASE[(index - i +offset) % len(SECOND_PHASE)]
        result += translated
    return result  

def found_infy_enc_data(line):    
    found_infy_str = "show=\"---------- Administration Reporting Service "
    found_infy_index = line.find(found_infy_str)
    if not found_infy_index==-1:
        return True,found_infy_index
    else:
        return False,found_infy_index
 
def extract_comp_name(line):
    comp = r"\xd\xa-----"
    comp_index = line.find(comp)
    comp_name = line[comp_index+len(comp):]
    comp_name = comp_name[:comp_name.find("-----")]
    print "(((=)))" + comp_name
    return comp_name
    
def extract_enc_data(line):
    header = r"\xd\xa_____"
    start_index = line.find(header)+len(header)
    line = line[start_index:]
    endindex = line.index("_____\" value=")
    line = line[:endindex]
    return line

def write_enc_infy_data_to_file(dec_line,comp_name,filename):                 
    file1 = open(filename + "\\" + comp_name + ".txt",'ab')
    file1.writelines(dec_line)
    file1.close()

def enc_wrapper(enc,comp_name):
    global FULL_KEY
    print FULL_KEY
    FULL_KEY = init_key(comp_name)
    
    enc_final = ""
    for letter in enc: 
            if len(hex(ord(letter))[2:])==1:
            enc_final += "0" + hex(ord(letter))[2:]  
        elif len(hex(ord(letter))[2:])==2:
            enc_final += hex(ord(letter))[2:]  
        else:
            print "not good hex length"
            exit()
            
    enc = enc_final.upper() 
   
    enc = enc.replace("2E","21") 
    enc = enc.replace("C5DC5A","") 
    enc = enc.replace("D03D00","")
    enc = enc.replace("0B0E","2121")  

    enc = enc.replace("01","21") 
     
    enc_len = len(enc)

    enc_rev = ""
    num_list = []
    enc_print =""
    for i in range(0,enc_len/2):
        enc_rev = enc[-2:]
        if not enc_rev=="0B" and not enc_rev=="0E" and not enc_rev=="00" and not enc_rev=="D0":
            enc_print +=enc_rev
            num_list.append(enc_rev)
        enc= enc[:-2]
    
    #the first part is always ok
    dec_str = decrypt(num_list,0)
    final = sub_1_for_hex(dec_str)
    index = final.find("OK: Sent")
    if index==-1:
        print comp_name + " - did not found OK: Sent !!!!\n\n\n\n"
        #exit()
    decrypt_data = comp_name + " ++==++ " +  str(i) + ": " + final + "\n"
    
    final_start = final[0:500]
    if final_start in UNIQUE_DATA:
          print comp_name + " already have this data"
          return
    UNIQUE_DATA.append(final_start)
    index = final.find("Installed Date:") 
    
    if index==-1:
        for i in range(1,61):
            dec_str = decrypt3(num_list,i)
            final = sub_1_for_hex(dec_str)
                 
            ##print all 62 options
            index2 = final.find("PROGRAM START:")
            index3 = final.find("Installed Date:")
            if not index2 ==-1 or not index3 ==-1:
                decrypt_data += str(i) + ": " + final + "\n"
    write_enc_infy_data_to_file(decrypt_data,comp_name,FILE_OUTPUT_NAME)

def read_enc_data_files():

    for root,dir,files in os.walk(PDML_PATH):
        for file in files:
            filename = root+ "\\" + file
            if os.path.isfile(filename):
                print filename
                for line in fileinput.input([filename]):
                    line = line.strip()
                    is_found,found_infy_index= found_infy_enc_data(line)
                    if not is_found:
                        continue
                    line = line[found_infy_index:]
                    
                    #get computer name (for use in init_key() later)
                    comp_name = extract_comp_name(line)
                    UNIQUE_COMP.append(comp_name)
                    #get the infy encrypted data
                    line = extract_enc_data(line)
                    #base64 decode enc_data
                    dec_line = line.decode('base64')
                    #append enc_data to file
                    write_enc_infy_data_to_file(dec_line,comp_name,FILE_ENC_OUTPUT_NAME)
                    enc_wrapper(dec_line,comp_name)
try:  
    read_enc_data_files()
except:
    print "exception!!!!"
