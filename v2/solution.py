#!/usr/bin/env python3
import sys,base64,lzma

# Each byte is either 255 (literal root) or transform<<5 | parent.
Z=[{'id':33,'preset':6}]
F={
 (b'IMG ',655360):bytes.fromhex('2929ff222eff2d21ffff2d2dff25ffff'),
 (b'CA30',253952):bytes.fromhex('2542ff2022ff7dff502fff28ff24ffffff4fffff24ff4822213739765d7127ff'),
 (b'A181',237600):bytes.fromhex('ffffffffffffffffffffffffffffffffffffff3fffffff27ffffffffffffffff'),
 (b'PRNG',240328):bytes.fromhex('ffffffffffff40ffffffffffff60ffffffffff66ffffff47'),
 (b'DUP ',174784):bytes.fromhex('ff2bffffffffff26ffffffff'),
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

def residual(cs,used):
 g={}
 for i,(t,p,n,x) in enumerate(cs):
  if i not in used:g.setdefault((t,0 if t==b'LOGS' else n),[]).append(i)
 return list(g.values())

def add(out,x):
 x=lzma.compress(x,format=3,filters=Z);out.extend(len(x).to_bytes(4,'big'));out.extend(x)

def compress(src,dst):
 data=base64.b64decode(open(src,'rb').read());cs=chunks(data);out=bytearray()
 add(out,data[:80]+b''.join(n.to_bytes(4,'big')+t+p for t,p,n,x in cs))
 used=set()
 for (tag,n),plan in F.items():
  ids=[i for i,c in enumerate(cs) if c[0]==tag and c[2]==n];assert len(ids)==len(plan);used.update(ids)
  for j,code in enumerate(plan):
   x=cs[ids[j]][3]
   if code!=255:x=delta(x,cs[ids[code&31]][3],code>>5)
   add(out,x)
 for ids in residual(cs,used):add(out,b''.join(cs[i][3] for i in ids))
 open(dst,'wb').write(out)

def take(a,o):
 n=int.from_bytes(a[o:o+4],'big');o+=4;return lzma.decompress(a[o:o+n],format=3,filters=Z),o+n

def decompress(src,dst):
 a=open(src,'rb').read();meta,o=take(a,0);cs=[]
 for q in range(80,len(meta),14):
  n=int.from_bytes(meta[q:q+4],'big');cs.append([meta[q+4:q+8],meta[q+8:q+14],n,None])
 used=set()
 for (tag,n),plan in F.items():
  ids=[i for i,c in enumerate(cs) if c[0]==tag and c[2]==n];used.update(ids);raw=[]
  for _ in ids:x,o=take(a,o);raw.append(x)
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
