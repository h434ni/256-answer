#!/usr/bin/env python3
import sys,base64,lzma
from hashlib import sha256

# Each byte is either 255 (literal root) or transform<<5 | parent.
Z=[{'id':33,'preset':7}]
F={
 (b'IMG ',655360):bytes.fromhex('2929ff222eff2d21ffff2d2dff25ffff'),
 (b'CA30',253952):bytes.fromhex('2542ff2022ff7dff502fff28ff24ffffff4fffff24ff4822213739765d7127ff'),
 (b'A181',237600):bytes.fromhex('ffffffffffffffffffffffffffffffffffffff3fffffff27ffffffffffffffff'),
 (b'PRNG',240328):bytes.fromhex('ffffffffffff40ffffffffffff60ffffffffff66ffffff47'),
 (b'DUP ',174784):bytes.fromhex('ff2affffffffff26ffffff'),
 (b'WAVE',131090):bytes.fromhex('ff43ffffff41ffff232822ff'),
 (b'SEQ2',174784):bytes.fromhex('64ff2421ffff'),
 (b'SEQ2',149991):bytes.fromhex('21ffff'),
}

def chunks(data):
 o=80;out=[]
 while o<len(data):
  n=int.from_bytes(data[o:o+4],'big');out.append([data[o+4:o+8],data[o+8:o+14],n,data[o+14:o+14+n]]);o+=14+n
 return out

def delta(child,parent,k):
 if k==1:return bytes(a^b for a,b in zip(child,parent))
 if k==2:return bytes((a-b)&255 for a,b in zip(child,parent))
 return bytes((b-a)&255 for a,b in zip(child,parent))

def undo(d,parent,k):
 if k==1:return bytes(a^b for a,b in zip(d,parent))
 if k==2:return bytes((a+b)&255 for a,b in zip(d,parent))
 return bytes((b-a)&255 for a,b in zip(d,parent))

def bm(a):
 C=B=1;L=0;m=-1;H=0
 for N,v in enumerate(a):
  H=H<<1|(v>>7);d=(C&H).bit_count()&1
  if d:
   T=C;C^=B<<(N-m)
   if 2*L<=N:L=N+1-L;B=T;m=N
 return C

def residual(cs,used):
 g={}
 for i,(t,p,n,x) in enumerate(cs):
  if i not in used:g.setdefault((t,p[1] if t==b'LOGS' else n),[]).append(i)
 K={b'LOGS':0,b'SPRS':2,b'NOIZ':5,b'SEQ2':3}
 for x in g.values():
  k=K.get(cs[x[0]][0])
  if k is not None:x.sort(key=lambda i:(cs[i][1][k],i),reverse=True)
 return list(g.values())

def add(out,x):
 x=lzma.compress(x,format=3,filters=Z);out.extend(len(x).to_bytes(4,'big'));out.extend(x)

def compress(src,dst):
 data=base64.b64decode(open(src,'rb').read());cs=chunks(data);out=bytearray()
 add(out,data[:80]+b''.join(n.to_bytes(4,'big')+t+p for t,p,n,x in cs))
 hs=[i for i,c in enumerate(cs) if c[0]==b'HASH' and c[1][1]==0];du=[i for i,c in enumerate(cs) if c[0]==b'DUP ' and c[1][-4:]==b'F\xbf\xa5\xf3'];mt=[i for i,c in enumerate(cs) if c[0]==b'MTST'];tc=[i for i,c in enumerate(cs) if c[0]==b'TOC '];s2=[i for i,c in enumerate(cs) if c[0]==b'SEQ2' and c[2]==31248];used=set(hs+du+mt+tc+s2)
 z=bytearray(b''.join(cs[i][3][:28]+cs[i][3][-4:] for i in hs)+b''.join(cs[i][3][-4:] for i in du+tc+s2))
 for mode,L in [(1,20188),(4,19937)]:
  C=bm(cs[next(i for i in mt if cs[i][1][1]==mode)][3][0::4][:50000]);assert C.bit_length()-1==L;z+=C.to_bytes((L+8)//8,'big')
 for i in mt:
  L=20188 if cs[i][1][1]==1 else 19937;x=cs[i][3];z+=x[:4*L]+x[-4:]
 add(out,z)
 for (tag,n),plan in F.items():
  ids=[i for i,c in enumerate(cs) if c[0]==tag and c[2]==n and i not in used];assert len(ids)==len(plan);used.update(ids)
  z=bytearray()
  for j,code in enumerate(plan):
   x=cs[ids[j]][3]
   if code!=255:x=delta(x,cs[ids[code&31]][3],code>>5)
   z+=x
  add(out,z)
 for ids in residual(cs,used):add(out,b''.join(cs[i][3] for i in ids))
 open(dst,'wb').write(out)

def take(a,o):
 n=int.from_bytes(a[o:o+4],'big');o+=4;return lzma.decompress(a[o:o+n],format=3,filters=Z),o+n

def decompress(src,dst):
 a=open(src,'rb').read();meta,o=take(a,0);cs=[]
 for q in range(80,len(meta),14):
  n=int.from_bytes(meta[q:q+4],'big');cs.append([meta[q+4:q+8],meta[q+8:q+14],n,None])
 hs=[i for i,c in enumerate(cs) if c[0]==b'HASH' and c[1][1]==0];du=[i for i,c in enumerate(cs) if c[0]==b'DUP ' and c[1][-4:]==b'F\xbf\xa5\xf3'];mt=[i for i,c in enumerate(cs) if c[0]==b'MTST'];tc=[i for i,c in enumerate(cs) if c[0]==b'TOC '];s2=[i for i,c in enumerate(cs) if c[0]==b'SEQ2' and c[2]==31248];z,o=take(a,o);used=set(hs+du+mt+tc+s2)
 for i in hs:
  e=z[:32];z=z[32:];n=cs[i][2];h=cs[i][1][-4:]+e[:28];x=bytearray(h[4:])
  while len(x)<n-4:h=sha256(h).digest();x+=h
  cs[i][3]=bytes(x[:n-4])+e[28:]
 for i in du:
  e=z[:4];z=z[4:];q=next(c for c in cs if c[0]==b'HASH' and c[1][-4:]==cs[i][1][-4:]);cs[i][3]=q[3][:cs[i][2]-4]+e
 for i in tc:
  e=z[:4];z=z[4:];cur=80;r=bytearray()
  for c in cs:
   cur+=14+c[2]
   if len(r)<1020:r+=cur.to_bytes(4,'big')
  cs[i][3]=bytes(r+e)
 for i in s2:
  e=z[:4];z=z[4:];p=cs[i][1];d=p[-1]-p[-2];s=(p[-1]+d)&255;n=cs[i][2];cs[i][3]=bytes((s+k*d)&255 for k in range(n-4))+e
 P={}
 for mode,L in [(1,20188),(4,19937)]:
  w=(L+8)//8;C=int.from_bytes(z[:w],'big');z=z[w:];P[mode]=(L,[k for k in range(1,L+1) if C>>k&1])
 for i in mt:
  n=cs[i][2];L,T=P[cs[i][1][1]];e=z[:4*L+4];z=z[4*L+4:];x=bytearray(n)
  for k in range(4):
   y=bytearray(e[k:4*L:4])
   while len(y)<n//4-1:
    j=len(y);v=0
    for q in T:v^=y[j-q]
    y.append(v)
   y.append(e[4*L+k]);x[k::4]=y
  cs[i][3]=bytes(x)
 for (tag,n),plan in F.items():
  ids=[i for i,c in enumerate(cs) if c[0]==tag and c[2]==n and i not in used];used.update(ids);x,o=take(a,o);raw=[x[j*n:(j+1)*n] for j in range(len(ids))]
  done=[None]*len(ids)
  def get(j):
   if done[j] is None:
    code=plan[j];done[j]=raw[j] if code==255 else undo(raw[j],get(code&31),code>>5)
   return done[j]
  for j,i in enumerate(ids):cs[i][3]=get(j)
 for ids in residual(cs,used):
  x,o=take(a,o);q=0
  for i in ids:n=cs[i][2];cs[i][3]=x[q:q+n];q+=n
 assert o==len(a) and all(c[3] is not None for c in cs)
 data=bytearray(meta[:80])
 for t,p,n,x in cs:data+=n.to_bytes(4,'big')+t+p+x
 open(dst,'wb').write(base64.b64encode(data))

if __name__=='__main__':
 (compress if sys.argv[1]=='--compress' else decompress)(sys.argv[2],sys.argv[3])
