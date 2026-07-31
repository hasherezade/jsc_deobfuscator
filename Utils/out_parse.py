#!/usr/bin/env python3
import sys
import re
import argparse
from dataclasses import dataclass

###

def merge_strings(l):
    patt1 = "\" + \""
    l = l.replace(patt1, '')
    return l

####

def __init__(self, line):
    self.line = merge_strings(line)
    self.strings = []
    #self.tokens = analyze_code(self.line)
    # fetch strings
    match = re.findall(r'"([^"]*)"', self.line)
    for str1 in match:
        self.strings.append(str1.strip())
        
###

@dataclass
class FunctionInfo:
    name: str
    args: list[str]
    lines: list[str]
    strings: list[str]

    def __init__(self, name, args):
        self.name = name
        self.args = args
        self.lines = []
        self.strings = []

    def add_line(self, line: str):
        line = line.rstrip()
        self.lines.append(line)
        
        line = merge_strings(line)
        match = re.findall(r'"([^"]*)"', line)
        for str1 in match:
            self.strings.append(str1.strip())

    def print_lines(self, lineno):
        i = 0
        for l in self.lines:
            if (lineno):
                print("%d : %s" % (i, l))
            else:
                print("%s" % (l))
            i+=1
    
    def print_strings(self):
        for s in self.strings:
            print(f'"{s}"')

    def has_string(self, searched_str, case_sens=False, full_str=False):
        if searched_str in self.strings:
            return True
        for s in self.strings:
            if not case_sens:
                s = s.lower()
                searched_str = searched_str.lower()
            if full_str:
                if s == searched_str:
                    return True
            else:
                if searched_str in s:
                    return True
        return False

    def print_header(self):
        #print(self.name + str(self.args))
        print("NAME: %s ARGS: %d (%s) LINES: %d STRINGS: %d" % (self.name, len(self.args), self.args, len(self.lines), len(self.strings)))
####


def parse_function(line):
    line = line.strip()
    pattern = re.compile(r"function\s+(\w+)\s*\((.*?)\)")
    match = re.findall(pattern, line)
    if not match:
        return None
    func_name = match[0][0]
    arg_string = match[0][1]
    arg_list = [arg.strip() for arg in arg_string.split(',')] if arg_string else []
    func = FunctionInfo(func_name, arg_list)
    func.add_line(line)
    return func

def process_file(filename, functions):
    assignments = {}
    last_func = None
    with open(filename, 'r') as file:
        for line in file:
            l = line.strip()

            func = parse_function(line)
            if func:
                last_func = func
                functions.append(func)
                
            else:
                if last_func:
                    last_func.add_line(line.rstrip())


def show_functions_by_string(functions, searched_str, lineno, case_sens=False, full_str=False):
    for func in functions:
        if func.has_string(searched_str, case_sens, full_str):
            #func.print_header()
            func.print_lines(lineno)

def get_function_by_name(functions, func_name, lineno):
    for func in functions:
        if func.name == func_name:
            #func.print_header()
            func.print_lines(lineno)
            return func
    return None

def main():
    parser = argparse.ArgumentParser(description="Parser for the decompiled JS files. Allow to search for functions by selected criteria.")
    parser.add_argument('--inp',dest="inp",default=None,help="Input JS file", required=True)
    parser.add_argument('--str',dest="str",default="",help="String to be find in function", required=False)
    parser.add_argument('--const',dest="const",default="",help="String const to be find in function", required=False)
    parser.add_argument('--func',dest="func",default="",help="Function to be displayed", required=False)
    parser.add_argument('--lineno',dest="lineno",action='store_true',help="Print number before each line", required=False)
    args = parser.parse_args()

    filename = args.inp
    functions = []
    process_file(filename, functions)

    show = True
    if (args.str):
        show_functions_by_string(functions, args.str, args.lineno)
        show = False

    if (args.const):
        show_functions_by_string(functions, args.const, args.lineno, True, True)
        show = False

    if (args.func):
        get_function_by_name(functions, args.func, args.lineno)
        show = False
    
    if (show):
        for func in functions:
            if len(func.strings):
                print("NAME: %s ARGS: %d (%s) LINES: %d STRINGS: %d" % (func.name, len(func.args), func.args, len(func.lines), len(func.strings)))
                func.print_strings()


if __name__ == "__main__":
    sys.exit(main())
