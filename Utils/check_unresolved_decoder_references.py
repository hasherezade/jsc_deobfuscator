#!/usr/bin/env python3
"""Find direct references/calls to resolved string-decoder helpers in final text.

Self-delegating decoder root stubs are excluded. Match starts inside quoted
embedded source strings are ignored.
"""
import argparse, csv, re

NAME_RE = re.compile(r'\b(func_[A-Za-z0-9_$]+_0x[0-9a-f]+)\s*\(')
DEF_RE = re.compile(r'^\s*function\s+(func_[A-Za-z0-9_$]+_0x[0-9a-f]+)\s*\(')

def outside_string(text, pos):
    quote=None; escaped=False
    for c in text[:pos]:
        if escaped:
            escaped=False
        elif c=='\\':
            escaped=True
        elif quote:
            if c==quote: quote=None
        elif c in "\"'":
            quote=c
    return quote is None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    ap.add_argument('--csv', required=True)
    args=ap.parse_args()
    names=set()
    with open(args.csv,newline='',encoding='utf-8',errors='replace') as f:
        for row in csv.reader(f):
            if row and row[0].startswith('func_'): names.add(row[0])
    current=None; found=[]
    with open(args.output,encoding='utf-8',errors='replace') as f:
        for lineno,line in enumerate(f,1):
            dm=DEF_RE.match(line)
            if dm: current=dm.group(1)
            for m in NAME_RE.finditer(line):
                name=m.group(1)
                if name not in names or not outside_string(line,m.start()): continue
                if dm and name==dm.group(1) and m.start(1)==dm.start(1): continue
                if current==name: continue  # expected self-delegating root stub
                found.append((lineno,current,name,line.strip()))
    for lineno,current,name,line in found:
        print(f'{lineno}: {current}: {name}\n    {line}')
    print(f'Unresolved decoder references: {len(found)}')
    raise SystemExit(1 if found else 0)
if __name__=='__main__': main()
