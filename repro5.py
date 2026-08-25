from glamdring.normalize import normalize_record
from glamdring.normalize.cef import parse_line
from glamdring.graph.extract import extract
from glamdring.report.narrative import is_key_event, describe
L=[l for l in open('samples/perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]

print('=== A) tal cual sale hoy ===')
e=normalize_record(parse_line(L[10]))
print(' activity=',e.activity,'actor=',e.actor,'src=',e.src,'key=',is_key_event(e))
print(' frase:',describe(e))
print(' aristas:',[(a.source,a.type,a.target) for a in extract(e)[1]])

print()
print('=== B) SOLO el cambio propuesto en cef.py:343 (activity=logon_remote) ===')
e=normalize_record(parse_line(L[10]))
e.activity='logon_remote'
print(' key=',is_key_event(e))
print(' frase:',describe(e))
print(' aristas:',[(a.source,a.type,a.target) for a in extract(e)[1]])
print(' nodos:',[n.key for n in extract(e)[0]])
