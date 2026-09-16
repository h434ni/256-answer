#!/usr/bin/env python3
import sys,base64,lzma,math
from hashlib import sha256

# Each byte is either 255 (literal root) or transform<<5 | parent.
Z=[{'id':33,'preset':7}]
F={
 (b'IMG ',655360):bytes.fromhex('2929ff222eff2d21ffff2d2dff25ffff'),
 (b'CA30',253952):bytes.fromhex('2542ff20ffff7dff502fff28ffffffffff4ffffffeff4822213739765d7127ff'),
 (b'A181',237600):bytes.fromhex('ffffffffffffffffffffffffffffffffffffff3fffffff27ffffffffffffffff'),
 (b'PRNG',240328):bytes.fromhex('ffffffffffff40ffffffffffff60ffffffffff66ffffff47'),
 (b'DUP ',174784):bytes.fromhex('ff2affffffffff26ffffff'),
 (b'WAVE',131090):bytes.fromhex('ff43ffffff41ffff232822ff'),
 (b'SEQ2',174784):bytes.fromhex('64ff2421ffff'),
 (b'SEQ2',149991):bytes.fromhex('21ffff'),
 (b'SEQ2',124992):bytes.fromhex('fffffd'),
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

def lane(x,w,r=0):
 if not r:return b''.join(x[i::w] for i in range(w))
 y=bytearray(len(x));o=0
 for i in range(w):n=len(y[i::w]);y[i::w]=x[o:o+n];o+=n
 return bytes(y)

def pred(x,r=0,L=32):
 y=bytearray(x)
 for i in range(L,len(y)):y[i]=((y[i]+y[i-L]) if r else (x[i]-x[i-L]))&255
 return bytes(y)

def wpred(x,w,lag,en,r=0):
 y=bytearray(x);M=1<<(8*w)
 for i in range(lag*w,len(x)-w+1,w):
  a=int.from_bytes(x[i:i+w],en);v=y if r else x;p=int.from_bytes(v[i-lag*w:i-(lag-1)*w],en);q=(a+p if r else a-p)%M;y[i:i+w]=q.to_bytes(w,en)
 return bytes(y)

def ca(seed,n):
 x=int.from_bytes(seed,'big');M=(1<<2048)-1;o=bytearray(seed)
 while len(o)<n:
  x=((x<<1)^(x|(x>>1)))&M;o+=x.to_bytes(256,'big')
 return bytes(o[:n])

def bm(a):
 C=B=1;L=0;m=-1;H=0
 for N,v in enumerate(a):
  H=H<<1|(v>>7);d=(C&H).bit_count()&1
  if d:
   T=C;C^=B<<(N-m)
   if 2*L<=N:L=N+1-L;B=T;m=N
 return C


def lfit(w,n=624,m=227):
 B=[None]*128;rank=0
 for i in range(192):
  q=w[i]|w[i+1]<<32|w[i+m]<<64|w[i+m+1]<<96;y=w[i+n]
  while q:
   p=q.bit_length()-1;v=B[p]
   if v is None:B[p]=(q,y);rank+=1;break
   q^=v[0];y^=v[1]
  assert q or not y
 assert rank==128
 return B

def lp(q,B):
 y=0
 while q:
  p=q.bit_length()-1;v=B[p];q^=v[0];y^=v[1]
 return y

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
 hs=[i for i,c in enumerate(cs) if c[0]==b'HASH' and c[1][1]==0];du=[i for i,c in enumerate(cs) if c[0]==b'DUP ' and c[1][-4:]==b'F\xbf\xa5\xf3'];mt=[i for i,c in enumerate(cs) if c[0]==b'MTST'];tc=[i for i,c in enumerate(cs) if c[0]==b'TOC '];s2=[i for i,c in enumerate(cs) if c[0]==b'SEQ2' and c[2]==31248];cn=[i for i,c in enumerate(cs) if c[0]==b'CNST' and c[1][0]>0];used=set(hs+du+mt+tc+s2+cn)
 z=bytearray(b''.join(cs[i][3][:28]+cs[i][3][-4:] for i in hs)+b''.join(cs[i][3][-4:] for i in du+tc+s2+cn))
 C=bm(cs[next(i for i in mt if cs[i][1][1]==1)][3][0::4][:50000]);assert C.bit_length()-1==20188;z+=C.to_bytes((20188+8)//8,'big')
 for i in mt:
  if cs[i][1][1]==1:z+=cs[i][3][:4*20188]+cs[i][3][-4:]
 m4=[i for i in mt if cs[i][1][1]==4]
 def words4(i):
  d=cs[i][1][-4:]+cs[i][3][:-4];return [int.from_bytes(d[j:j+4],'big') for j in range(0,len(d)-3,4)]
 B=lfit(words4(m4[0]))
 for q,y in B:z+=q.to_bytes(16,'big')+y.to_bytes(4,'big')
 for i in m4:
  d=cs[i][1][-4:]+cs[i][3][:-4];z+=d[:2496]+d[len(d)//4*4:]+cs[i][3][-4:]
 add(out,z)
 for (tag,n),plan in F.items():
  ids=[i for i,c in enumerate(cs) if c[0]==tag and c[2]==n and i not in used];assert len(ids)==len(plan);used.update(ids)
  z=bytearray()
  for j,code in enumerate(plan):
   x=cs[ids[j]][3]
   if tag==b'SEQ2' and n==124992 and code==253:
    d=cs[ids[1]][1][-4:]+cs[ids[1]][3][:-4];q=b''.join(int.from_bytes(d[k:k+4],'big').to_bytes(4,'little') for k in range(n-4,-1,-4));assert q==cs[ids[j]][1][-4:]+x[:-4];z+=x[-4:]+bytes(n-4);continue
   if tag==b'CA30' and code==254:
    d=cs[ids[j]][1][-4:]+x[:-4];assert ca(d[:256],n)==d;x=x[:252]+x[-4:]+bytes(n-256);z+=x;continue
   if tag==b'CA30' and code==255 and j in {2,4,13,20}:
    x=x[-4:]+bytes(n-4);z+=x;continue
   if code!=255:x=delta(x,cs[ids[code&31]][3],code>>5)
   w={b'IMG ':3,b'WAVE':2}.get(tag)
   if w:x=lane(x,w)
   if tag==b'IMG ' and j in {2: 4, 5: 1, 6: 2048, 8: 1, 9: 1, 12: 2048, 14: 4, 15: 1}:x=pred(x,0,{2: 4, 5: 1, 6: 2048, 8: 1, 9: 1, 12: 2048, 14: 4, 15: 1}[j])
   if tag==b'A181' and j in {1: 4, 2: 4, 10: 16, 12: 4, 15: 16, 16: 4, 17: 4, 26: 4, 30: 4}:x=lane(x,{1: 4, 2: 4, 10: 16, 12: 4, 15: 16, 16: 4, 17: 4, 26: 4, 30: 4}[j])
   if tag==b'A181' and j in {12: 1}:x=pred(x,0,{12: 1}[j])
   if tag==b'SEQ2' and n==124992 and j==1:x=wpred(x,4,2,'big')
   if tag==b'CA30':x=pred(x)
   z+=x
  add(out,z)
 rg=residual(cs,used);cm={1:(1,4),6:(6,7),12:(12,13)};skip={4,7,13}
 for k,ids in enumerate(rg):
  if k in skip:continue
  ks=cm.get(k,(k,));add(out,b''.join(cs[i][3] for j in ks for i in rg[j]))
 open(dst,'wb').write(out)

def take(a,o):
 n=int.from_bytes(a[o:o+4],'big');o+=4;return lzma.decompress(a[o:o+n],format=3,filters=Z),o+n

def decompress(src,dst):
 a=open(src,'rb').read();meta,o=take(a,0);cs=[]
 for q in range(80,len(meta),14):
  n=int.from_bytes(meta[q:q+4],'big');cs.append([meta[q+4:q+8],meta[q+8:q+14],n,None])
 hs=[i for i,c in enumerate(cs) if c[0]==b'HASH' and c[1][1]==0];du=[i for i,c in enumerate(cs) if c[0]==b'DUP ' and c[1][-4:]==b'F\xbf\xa5\xf3'];mt=[i for i,c in enumerate(cs) if c[0]==b'MTST'];tc=[i for i,c in enumerate(cs) if c[0]==b'TOC '];s2=[i for i,c in enumerate(cs) if c[0]==b'SEQ2' and c[2]==31248];cn=[i for i,c in enumerate(cs) if c[0]==b'CNST' and c[1][0]>0];z,o=take(a,o);used=set(hs+du+mt+tc+s2+cn)
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
 for i in cn:
  e=z[:4];z=z[4:];p=cs[i][1];n=cs[i][2];N=n+4;q=(2,3,5,7)[p[0]];x=(math.isqrt(q<<(16*N))%(1<<(8*N))).to_bytes(N,'big')
  if p[0]==1:x=bytes((v+j)&255 for j,v in enumerate(x))
  cs[i][3]=x[4:n]+e
 L=20188;w=(L+8)//8;C=int.from_bytes(z[:w],'big');z=z[w:];T=[k for k in range(1,L+1) if C>>k&1]
 for i in [i for i in mt if cs[i][1][1]==1]:
  n=cs[i][2];e=z[:4*L+4];z=z[4*L+4:];x=bytearray(n)
  for k in range(4):
   y=bytearray(e[k:4*L:4])
   while len(y)<n//4-1:
    j=len(y);v=0
    for q in T:v^=y[j-q]
    y.append(v)
   y.append(e[4*L+k]);x[k::4]=y
  cs[i][3]=bytes(x)
 B=[]
 for p in range(128):B.append((int.from_bytes(z[:16],'big'),int.from_bytes(z[16:20],'big')));z=z[20:]
 for i in [i for i in mt if cs[i][1][1]==4]:
  n=cs[i][2];r=n%4;e=z[:2496+r+4];z=z[2496+r+4:];w4=[int.from_bytes(e[j:j+4],'big') for j in range(0,2496,4)]
  while len(w4)<n//4:
   j=len(w4)-624;q=w4[j]|w4[j+1]<<32|w4[j+227]<<64|w4[j+228]<<96;w4.append(lp(q,B))
  d=b''.join(v.to_bytes(4,'big') for v in w4)+e[2496:2496+r];assert d[:4]==cs[i][1][-4:];cs[i][3]=d[4:]+e[-4:]
 for (tag,n),plan in F.items():
  ids=[i for i,c in enumerate(cs) if c[0]==tag and c[2]==n and i not in used];used.update(ids);x,o=take(a,o);raw=[x[j*n:(j+1)*n] for j in range(len(ids))]
  w={b'IMG ':3,b'WAVE':2}.get(tag)
  if tag==b'IMG ':
   for j,L in {2: 4, 5: 1, 6: 2048, 8: 1, 9: 1, 12: 2048, 14: 4, 15: 1}.items():raw[j]=pred(raw[j],1,L)
  if tag==b'A181':
   for j,L in {12: 1}.items():raw[j]=pred(raw[j],1,L)
   for j,L in {1: 4, 2: 4, 10: 16, 12: 4, 15: 16, 16: 4, 17: 4, 26: 4, 30: 4}.items():raw[j]=lane(raw[j],L,1)
  if tag==b'SEQ2' and n==124992:
   raw[1]=wpred(raw[1],4,2,'big',1);d=cs[ids[1]][1][-4:]+raw[1][:-4];q=b''.join(int.from_bytes(d[k:k+4],'big').to_bytes(4,'little') for k in range(n-4,-1,-4));raw[2]=q[4:]+raw[2][:4]
  if w:raw=[lane(y,w,1) for y in raw]
  if tag==b'CA30':
   for j,y in enumerate(raw):
    if plan[j]==254:
     d=ca(cs[ids[j]][1][-4:]+y[:252],n);raw[j]=d[4:]+y[252:256]
    elif plan[j]==255 and j in {2,4,13,20}:
     seed=bytearray(256);seed[123]=1;d=ca(seed,n);raw[j]=d[:-4]+y[:4]
    else:raw[j]=pred(y,1)
  done=[None]*len(ids)
  def get(j):
   if done[j] is None:
    code=plan[j];done[j]=raw[j] if code in (253,254,255) else undo(raw[j],get(code&31),code>>5)
   return done[j]
  for j,i in enumerate(ids):cs[i][3]=get(j)
 rg=residual(cs,used);cm={1:(1,4),6:(6,7),12:(12,13)};skip={4,7,13}
 for k,ids in enumerate(rg):
  if k in skip:continue
  x,o=take(a,o);q=0
  for j in cm.get(k,(k,)):
   for i in rg[j]:n=cs[i][2];cs[i][3]=x[q:q+n];q+=n
 assert o==len(a) and all(c[3] is not None for c in cs)
 data=bytearray(meta[:80])
 for t,p,n,x in cs:data+=n.to_bytes(4,'big')+t+p+x
 open(dst,'wb').write(base64.b64encode(data))

if __name__=='__main__':
 (compress if sys.argv[1]=='--compress' else decompress)(sys.argv[2],sys.argv[3])
