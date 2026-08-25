import sys, dataclasses
sys.path.insert(0, r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING')
from glamdring.normalize import normalize_record
from glamdring.normalize.cef import parse_line
from glamdring.graph.extract import extract
L=[l for l in open(r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING\samples\perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
for i,l in enumerate(L,1):
    e=normalize_record(parse_line(l))
    n,ed=extract(e)
    print('---',i, e.activity, e.class_name)
    d=dataclasses.asdict(e) if dataclasses.is_dataclass(e) else vars(e)
    print('  fields:', {k:v for k,v in d.items() if v not in (None,'',[],{})})
    print('  edges:', [(x.source,x.relation,x.target) if hasattr(x,'relation') else vars(x) for x in ed])
