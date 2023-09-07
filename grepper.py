import re
import sys
import json

def find_functions(input_filename):
    with open(input_filename, 'r') as input_file:
        file_content = input_file.read()
        pattern = r'^(?!(?:#ifndef|#if))\w+\s+\w*\s*(?:WINAPI|NTAPI)\s+[^_]+\s*\([^;]+\);'
        return re.findall(pattern, file_content, flags=re.I|re.M)

def populate_obj_with_functions(functions, library_name,obj):
    for function in functions:
        #<useless> <data type> WINAPI|NTAPI <function name>(parameters); 
        useless = ["WINBASEAPI", "__KERNEL_ENTRY","_Ret_maybenull_", "WINUSERAPI"]
      
        # remove \n and white spaces
        function = function.replace("\n", " ")
        function = " ".join(function.split())
        #remove useless keywords
        for i in useless:
            function = function.split(" ")
            if i in function: function.pop(function.index(i))
            function = " ".join(function)
        
        # get function name
        function_name = function.split(" ")[2];
        if function_name.find("("): function_name = function_name.split("(")[0];

        obj.update({function_name:{"signature":function,"library":library_name}})

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("python main.py <input directory> <output filename>")
        exit(1)
    
    input_directory = sys.argv[1]
    output_filename = sys.argv[2]

    function_dict = {};
    functions = []
    header_files = [
        [r"\um\winuser.h","user32.dll"],
        [r"\um\memoryapi.h","kernel32.dll"],
        [r"\um\psapi.h","kernel32.dll"],
        [r"\um\tlhelp32.h","kernel32.dll"],
        [r"\um\debugapi.h","kernel32.dll"],
        [r"\um\processthreadsapi.h","kernel32.dll"],
        [r"\um\fileapi.h","kernel32.dll"],
        [r"\um\libloaderapi.h","kernel32.dll"]
    ]
    for file in header_files:
        functions = find_functions(input_directory + file[0])
        populate_obj_with_functions(functions,  file[1],function_dict)

    with open(output_filename, "w") as output_file:
        output_file.write(json.dumps(function_dict))