import sys
sys.path.insert(0, r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING')
from glamdring.normalize import normalize_record
from glamdring.normalize.cef import parse_line
from glamdring.report.narrative import describe, is_key_event, summarize_events
L=[l for l in open(r'C:\Users\JuanLopez\Downloads\AUTOMATA\GLAMDRING\samples\perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
evs=[normalize_record(parse_line(l)) for l in L]
e8=evs[7]
print('antes describe: key=',is_key_event(e8),'mitre=',e8.mitre,'sev=',e8.severity)
t=describe(e8)
print('despues describe: key=',is_key_event(e8),'mitre=',e8.mitre,'sev=',e8.severity)
ents=summarize_events(evs)
print('uids en cronologia:',[x['uids'] for x in ents])
print('uid e8:',e8.uid, 'key ahora:', is_key_event(e8))
print('uids l1..l11:',[e.uid for e in evs])
