import sys
sys.path.insert(0, r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING')
from glamdring.normalize import normalize_record
from glamdring.normalize.cef import parse_line
from glamdring.report.narrative import describe, summarize_events, is_key_event
L=[l for l in open(r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING\samples\perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
evs=[normalize_record(parse_line(l)) for l in L]
for i,e in enumerate(evs,1):
    print(i, '|', describe(e))
print('=== CRONOLOGIA ===')
for en in summarize_events(evs):
    print(en['time'], '|', en['text'])
