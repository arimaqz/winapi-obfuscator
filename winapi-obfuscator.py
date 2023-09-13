import re
import sys
import os
import json
import string
from random import choice
import argparse

class Grepper:
    __header_files = [
        [r"\um\winuser.h","user32.dll"],
        [r"\um\memoryapi.h","kernel32.dll"],
        [r"\um\psapi.h","kernel32.dll"],
        [r"\um\tlhelp32.h","kernel32.dll"],
        [r"\um\debugapi.h","kernel32.dll"],
        [r"\um\processthreadsapi.h","kernel32.dll"],
        [r"\um\fileapi.h","kernel32.dll"],
        [r"\um\libloaderapi.h","kernel32.dll"]
    ]

    __pattern = r'^(?!(?:#ifndef|#if))\w+\s+\w*\s*(?:WINAPI|NTAPI)\s+[^_]+\s*\([^;]+\);'
    __useless = ["WINBASEAPI", "__KERNEL_ENTRY","_Ret_maybenull_", "WINUSERAPI"]
    
    __functions_list = []
    __data_dict = {}

    def __init__(self,windows_sdk_path) -> None:
        self.windows_sdk_path = windows_sdk_path
        
    def __find_functions(self,input_filename):
        with open(input_filename, 'r') as input_file:
            file_content = input_file.read()
            self.__functions_list = re.findall(self.__pattern, file_content, flags=re.I|re.M)

    def __populate_data_dict(self, library_name):
        for function in self.__functions_list:
            #<useless> <data type> WINAPI|NTAPI <function name>(parameters) {stuff}; 
            # = <data type> WINAPI/NTAPI <functio name>(parameters);
             
            # remove \n and white spaces
            function = function.replace("\n", " ")
            function = " ".join(function.split())

            # some functions have a {} body as well
            if function.find("{") != -1: function = function.split("{")[0] + ";"

            #remove useless keywords
            for i in self.__useless:
                function = function.split(" ")
                if i in function: function.pop(function.index(i))
                function = " ".join(function)
            
            # get function name
            function_name = function.split(" ")[2];
            if function_name.find("("): function_name = function_name.split("(")[0];

            self.__data_dict.update({function_name:{"signature":function,"library":library_name}})

    def grep(self):
        for file in self.__header_files:
            self.__find_functions(self.windows_sdk_path+file[0])
            self.__populate_data_dict(file[1],)
        return self.__data_dict

class Encryption:
    def __init__(self, length=10) -> None:
        self.letters = string.ascii_lowercase+string.ascii_uppercase+string.digits
        self.length = length
    def __XOR_key_generator(self,length):
        "generate random XOR key"
        key = ""
        for i in range(length):
            key += choice(self.letters)
        return key
    def XOR(self,data:bytes):
        "XOR data with specified key"
        key = self.__XOR_key_generator(self.length)
        data_array = bytearray(data) #modifable when bytearray    
        for i in range(len(data_array)):
            current_key = key[i % len(key)]
            data_array[i] ^=  ord(current_key)
        return [bytes(data_array),key]
    
class Obfuscation(Encryption):

    # PREFIXES/NAMES
    __new_function_definition_prefix = "p"
    __ciphertext_variable_prefix = "s"
    __key_variable_prefix = "k"
    __xor_decryption_function_name = "XOR"

    __missing_functions = []
    __libraries = []
    __output_obj = {"__new_function_definitions":[],"ciphertexts":[],"keys":[],"decryption_function_calls":[],"__resolve_functions":[]}


    def __init__(self, data_dict,functions_list,key_length) -> None:
        super().__init__(key_length)            

        self.data_dict = data_dict
        self.functions_list = functions_list

    def __new_function_definition(self,plaintext):
        "save new function definition to file"
        #<data type> WINAPI <function name>(parameters);
        # > 
        #typedef <data type> (WINAPI *<prefix><function name>)(parameters);

        signature = self.data_dict[plaintext]["signature"]
        signature = signature.split(" ")
        # preppend '(' to WINAPI/NTAPI
        signature[1] = "(" + signature[1] 
        # prepend '* <prefix>' to function name and uppercase the first letter
        signature[2] = "* " + self.__new_function_definition_prefix + signature[2][0].upper() +signature[2][1:]
        # replace '(' with ')('
        signature[2] = signature[2].replace("(", ")(")
        # join back
        signature = " ".join(signature)
        # prepend 'typedef' to the signature
        signature = "typedef " + signature

        return signature + "\n"

    def __resolve_function(self,plaintext):
        library = self.data_dict[plaintext]['library'].split('.')[0]
        library = self.__ciphertext_variable_prefix + library[0].upper() + library[1:]
        
        return f"{self.__new_function_definition_prefix}{plaintext} {plaintext[0].lower()+plaintext[1:]} = ({self.__new_function_definition_prefix}{plaintext})GetProcAddress(LoadLibraryA((LPCSTR){library}),(LPCSTR){self.__ciphertext_variable_prefix}{plaintext});\n"
    
    def obfuscator(self,plaintext,is_library=False):
            
        xor_result = self.XOR((plaintext.encode()+b'\x00'))
        ciphertext = xor_result[0]
        key = xor_result[1]
            
        #if it's a dll name get the text before .dll
        if plaintext.find(".") != -1: plaintext = plaintext.split('.')[0]
        #uppercase first letter
        plaintext = plaintext[0].upper()+plaintext[1:]

        ciphertext_value = "{" + ", ".join(hex(x) for x in ciphertext) + "}"
        ciphertext_whole = f"unsigned char {self.__ciphertext_variable_prefix}{plaintext}[] = {ciphertext_value};\n"
        
        key_value = "{" + ", ".join(hex(x) for x in (key.encode()+b"\x00")) + "}"   
        key_whole = f"char {self.__key_variable_prefix}{plaintext}[] = {key_value};\n"

        decryption_function_call = f"{self.__xor_decryption_function_name}({self.__ciphertext_variable_prefix}{plaintext}, sizeof({self.__ciphertext_variable_prefix}{plaintext}),  {self.__key_variable_prefix}{plaintext}, sizeof({self.__key_variable_prefix}{plaintext}));\n"
        
        if not is_library:
            __new_function_definition = self.__new_function_definition(plaintext)
            __resolve_function = self.__resolve_function(plaintext)
        
        self.__output_obj["ciphertexts"].append(ciphertext_whole)
        self.__output_obj["keys"].append(key_whole)
        self.__output_obj["decryption_function_calls"].append(decryption_function_call)
        if not is_library:
            self.__output_obj["__new_function_definitions"].append(__new_function_definition)
            self.__output_obj["__resolve_functions"].append(__resolve_function)
    
    def obfuscate(self):
        #obfuscate function names
        for function in self.functions_list:
            if function not in self.data_dict.keys():
                self.__missing_functions.append(function)
                continue
            if self.data_dict[function]["library"] not in self.__libraries: self.__libraries.append(self.data_dict[function]["library"])
            self.obfuscator(function)
        #obfuscate libraries
        for library in self.__libraries:
            self.obfuscator(library,True)

        return [self.__output_obj, self.__missing_functions]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-sdk","-s",help="Windows SDK path which is usually located at 'C:\Program Files (x86)\Windows Kits\\<windows version>\Include\\<version>'.", dest="windows_sdk",required=True)
    parser.add_argument("--function-names","-f",help="function names separated by ','.",dest="function_names",required=True)
    parser.add_argument("--key-length","-l",help="XOR key length. default is '10'.",dest="key_length",default=10)
    return parser.parse_args()

if __name__ == "__main__":

    options = parse_args()

    windows_sdk = options.windows_sdk
    function_names = options.function_names.split(',')
    key_length = int(options.key_length)
    data_dict = {}

    if "data.json" not in os.listdir(os.curdir):
        # generate json data
        grepper = Grepper(windows_sdk)
        data_dict = grepper.grep()

        # save json in file
        with open("data.json", "w") as f:
            f.write(json.dumps(data_dict))
            f.close()
    else:
        with open("data.json", "r") as f:
            data_dict = json.loads(f.read())

    # obfuscate
    obfuscation = Obfuscation(data_dict,function_names,key_length)
    output_obj, missing_functions = obfuscation.obfuscate()

    # save in file
    for key in list(output_obj.keys()):
        for item in output_obj[key]:
            with open("all.txt","a") as f:
                f.write(item)
                f.close()
        with open("all.txt","a") as f:
            f.write("\n")
            f.close()

    # missing functions
    for function in missing_functions:
        print(f"[!] {function} is missing.")
