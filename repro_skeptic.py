from glamdring.normalize import normalize_record
from glamdring.normalize.cef import parse_line
from glamdring.graph.extract import extract
from glamdring.report.narrative import is_key_event
from glamdring.models import ActorRef, HostRef
L=[l for l in open('samples/perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
e=normalize_record(parse_line(L[10]))
print('activity=',e.activity,'| is_key_event=',is_key_event(e))
print('actor=',e.actor,'src=',e.src,'dst=',e.dst,'host=',getattr(e,"host",None),'class=',e.class_name,'sev=',e.severity,'status=',e.status)
e.actor=ActorRef(user='jlopez'); e.src=HostRef(ip='10.4.2.11'); e.activity='logon_remote'
print('como logon_remote:',is_key_event(e),[(a.source,a.type,a.target) for a in extract(e)[1]])
