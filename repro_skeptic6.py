import sys
sys.path.insert(0, r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING')
from glamdring.normalize import normalize_record
from glamdring.normalize.cef import parse_line
import glamdring.normalize.base as B
L=[l for l in open(r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING\samples\perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
e=normalize_record(parse_line(L[7]))
print('L8:',e.class_name,e.activity,e.severity,e.status,e.uid)
