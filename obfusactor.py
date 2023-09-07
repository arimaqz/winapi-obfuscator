import sys
import json
import os
from random import choice


class Encryption:
    def __init__(self, length=10) -> None:
        self.length = length
    def __XOR_key_generator(self,length):
        "generate random XOR key"
        letters = 'abcdefghijklmnopqrstuvwxyz'
        key = ""
        for i in range(length):
            key += choice(letters)
        return key
    def XOR(self,data:bytes):
        "XOR data with specified key"
        key = self.__XOR_key_generator(self.length)
        data_array = bytearray(data) #modifable when bytearray    
        for i in range(len(data_array)):
            current_key = key[i % len(key)]
            data_array[i] ^=  ord(current_key)
        return [bytes(data_array),key]


class SaveToFile:

    # FILES/DIRECTORIES
    out_folder = "dist"
    keys_file = f"{out_folder}/keys.txt"
    decryption_function_calls_file = f"{out_folder}/decryption_calls.txt"
    ciphertexts_file = f"{out_folder}/encrypted_strings.txt"
    new_function_definitions_file = f"{out_folder}/definitions.txt"
    decryption_cpp_function_file = f"{out_folder}/decryption_function.txt"
    resolve_functions_file =  f"{out_folder}/resolve_functions.txt"
    # PREFIXES/NAMES
    new_function_definition_prefix = "p"
    ciphertext_variable_prefix = "s"
    key_variable_prefix = "k"
    xor_decryption_function_name = "XOR"


    def __init__(self,plaintext,ciphertext, key, function_obj,save_in_one_file=False):
        
        self.plaintext = plaintext
        #if it's a dll name get the text before .dll
        if self.plaintext.find(".") != -1: self.plaintext = self.plaintext.split('.')[0]
        #uppercase first letter
        self.plaintext = self.plaintext[0].upper()+self.plaintext[1:]
        
        self.ciphertext = ciphertext
        self.key = key
        self.function_obj = function_obj
        self.save_in_one_file = save_in_one_file

    def ciphertextF(self):
        "save encrypted string variable to file"
        #string 
        value = "{" + ", ".join(hex(x) for x in self.ciphertext) + "}"
        #uppercase the first letter
        output = f"unsigned char {self.ciphertext_variable_prefix}{self.plaintext}[] = {value};\n"
        if not self.save_in_one_file:
            with open(self.ciphertexts_file, "a") as f:
                f.write(output)
                return None
        return output
    def keyF(self):
        key_copy = "{" + ", ".join(hex(x) for x in (self.key.encode()+b"\x00")) + "}"   
        "save key variable to file"
        output = f"char {self.key_variable_prefix}{self.plaintext}[] = {key_copy};\n"
        if not self.save_in_one_file:
            with open(self.keys_file,"a") as f:
                f.write(output)
                return None
        return output
    def decryption_function_call(self):
        "save decryption function call to file"
        output = f"{self.xor_decryption_function_name}({self.ciphertext_variable_prefix}{self.plaintext}, sizeof({self.ciphertext_variable_prefix}{self.plaintext}),  {self.key_variable_prefix}{self.plaintext}, sizeof({self.key_variable_prefix}{self.plaintext}));\n"
        if not self.save_in_one_file:
            with open(self.decryption_function_calls_file,"a") as f:
                f.write(output)    
                return None
        return output
    def new_function_definition(self):
        #<data type> WINAPI <function name>(parameters);
        # > 
        #typedef <data type> (WINAPI *<prefix><function name>)(parameters);

        signature = self.function_obj["signature"]
        signature = signature.split(" ")

        
        # preppend '(' to WINAPI/NTAPI
        signature[1] = "(" + signature[1] 

        # prepend '* <prefix>' to function name and uppercase the first letter
        signature[2] = "* " + self.new_function_definition_prefix + signature[2][0].upper() +signature[2][1:]

        # replace '(' with ')('
        signature[2] = signature[2].replace("(", ")(")

        # join back
        signature = " ".join(signature)

        # prepend 'typedef' to the signature
        signature = "typedef " + signature
        output = signature + "\n"
        if not self.save_in_one_file:
            with open(self.new_function_definitions_file, "a") as f:
                f.write(output)
                return None
        return output
    def resolve_function(self):
        library = self.function_obj['library'].split('.')[0]
        library = self.ciphertext_variable_prefix + library[0].upper() + library[1:]
        output = f"{self.new_function_definition_prefix}{self.plaintext} {self.plaintext[0].lower()+self.plaintext[1:]} = ({self.new_function_definition_prefix}{self.plaintext})GetProcAddress(LoadLibraryA((LPCSTR){library}),(LPCSTR){self.ciphertext_variable_prefix}{self.plaintext});\n"
        if not self.save_in_one_file:
            with open(self.resolve_functions_file, 'a') as f:
                f.write(output)
                return None
        return output

if __name__ == "__main__":
    
    if len(sys.argv) < 4:
        print("python main.py <json file> <function names separated by comma> <save in one file y/n>")
        exit(1)
    data_obj = {}
    missing_functions = []
    libraries = []
    save_in_one_file = True if sys.argv[3] ==  "y" else False
    outputs = {"new_function_definitions":[],"ciphertexts":[],"keys":[],"decryption_function_calls":[],"resolve_functions":[]}
    
    with open(sys.argv[1],"r") as data:
        data_obj = json.loads(data.read())
    
    functions = sys.argv[2].split(',')


    if "dist" not in os.listdir():
        os.mkdir("dist")

    def run(function_object,library=None):
        if not library:
            plaintext = function_object["signature"].split(" ")[2]
            if plaintext.find("("): plaintext = plaintext.split("(")[0]
        else:
            plaintext = library
        encrypt = Encryption()
        xor_result = encrypt.XOR((plaintext.encode()+b'\x00'))
        ciphertext = xor_result[0]
        key = xor_result[1]

        if not library:
            if function_object["library"] not in libraries:
                libraries.append(function_object["library"])

        save = SaveToFile(plaintext,ciphertext,key, function_object,save_in_one_file)
        ciphertext_output = save.ciphertextF()
        key_output = save.keyF()
        decryption_function_call = save.decryption_function_call()
        if not library:
            new_function_definition = save.new_function_definition()
            resolve_function = save.resolve_function()

        if save_in_one_file:
            outputs["ciphertexts"].append(ciphertext_output)
            outputs["keys"].append(key_output)
            outputs["decryption_function_calls"].append(decryption_function_call)
            if not library:
                outputs["new_function_definitions"].append(new_function_definition)
                outputs["resolve_functions"].append(resolve_function)

    for function in functions:
        if function not in data_obj.keys():
            missing_functions.append(function)
            continue
        run(data_obj[function])

    for library in libraries:
        run(None,library)
    
    if save_in_one_file:
        for i in range(len(list(outputs.keys()))):
            for item in outputs[list(outputs.keys())[i]]:
                with open("all.txt","a") as f:
                    f.write(item)
            with open("all.txt","a") as f:
                f.write("\n")
        
    for missing_functions_function in missing_functions:
        print(f"\"{missing_functions_function}\" is missing from {sys.argv[1]} file.")
