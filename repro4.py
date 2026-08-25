from glamdring.normalize.cef import parse_line
from glamdring.normalize.base import registry
L=[l for l in open('samples/perimeter.cef',encoding='utf-8').read().splitlines() if l.strip()]
for i in (8,9,10):
    rec=parse_line(L[i])
    hits=[(p,n,m(rec)) for p,n,m,_ in registry()]
    winner=next((n for p,n,m,_ in registry() if m(rec)),None)
    print('linea',i+1,'| GANA:',winner,'|',hits)
