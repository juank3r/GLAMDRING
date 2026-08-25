import sys
sys.path.insert(0, r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING')
from glamdring.normalize import normalize_record
from glamdring.normalize.cef import parse_line
from glamdring.graph.extract import extract
from glamdring.report.narrative import is_key_event
L=[l for l in open(r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING\samples\perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
for i,l in enumerate(L,1):
    e=normalize_record(parse_line(l))
    print(i,e.class_name,'|',e.activity,'|',e.severity,'|',e.status,'|',is_key_event(e),'|',[x.key for x in extract(e)[0]])
