from glamdring.normalize.cef import parse_line
from glamdring.normalize import normalize_all
from glamdring.graph.build import build_graph
from glamdring.report.narrative import summarize_events
L=[l for l in open('samples/perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
recs=[parse_line(l) for l in L]
evs=normalize_all([r for r in recs if r])
print('eventos:',len(evs))
g=build_graph(evs)
edges=getattr(g,'edges',None)
try:
    lst=list(edges)
except TypeError:
    lst=list(edges())
print('tipos de arista:',sorted({getattr(e,"type",None) for e in lst}))
print('LATERAL:',[ (e.source,e.type,e.target) for e in lst if getattr(e,'type',None)=='lateral'])
print()
print('CRONOLOGIA:')
for item in summarize_events(evs):
    print('  -',item)
