#!/usr/bin/env python3
"""Data-only ZIP copy/literal delta for an already signed APK. No signing keys."""
import argparse,base64,gzip,hashlib,io,json,mmap,struct,zipfile
from pathlib import Path
BASE_SHA='c2dc6160ac7b8ec1bbdc2c529f26d69d1b9e4381d3fd6245e5fda4c4ce11aa02'
BASE_URL='https://github.com/JMosh89/Walkcraft-Descargas/releases/download/v0.8.0/Walkcraft-Android-0.8.0-Normal.apk'
ASSET='Walkcraft-Android-0.8.2-Normal.apk'
def sha_file(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def positions(z,data):
 result={}
 for info in z.infolist():
  off=info.header_offset
  if data[off:off+4]!=b'PK\x03\x04':raise ValueError('Local ZIP header missing')
  names,extra=struct.unpack_from('<HH',data,off+26);body=off+30+names+extra;end=body+info.compress_size
  result[info.filename]=(off,body,end)
 return result
def generate(baseline,signed,destination):
 if sha_file(baseline)!=BASE_SHA:raise ValueError('Baseline identity mismatch')
 with open(baseline,'rb') as bf,open(signed,'rb') as nf,mmap.mmap(bf.fileno(),0,access=mmap.ACCESS_READ) as old,mmap.mmap(nf.fileno(),0,access=mmap.ACCESS_READ) as new,zipfile.ZipFile(baseline) as oz,zipfile.ZipFile(signed) as nz:
  op,np=positions(oz,old),positions(nz,new);ops=[];cursor=0;copied=0
  def literal(start,end):
   if end>start:ops.append([1,base64.b64encode(new[start:end]).decode()])
  def same(a,start,end,b,bs,be):return end-start==be-bs and hashlib.sha256(memoryview(a)[start:end]).digest()==hashlib.sha256(memoryview(b)[bs:be]).digest()
  for name,(start,body,end) in sorted(np.items(),key=lambda x:x[1][0]):
   literal(cursor,start);prior=op.get(name)
   if prior and same(new,start,end,old,prior[0],prior[2]):ops.append([0,prior[0],end-start]);copied+=end-start
   elif prior and same(new,body,end,old,prior[1],prior[2]):literal(start,body);ops.append([0,prior[1],end-body]);copied+=end-body
   else:literal(start,end)
   cursor=end
  literal(cursor,len(new));patch={'schema':1,'base':{'sha256':BASE_SHA,'size':len(old),'url':BASE_URL},'output':{'name':ASSET,'sha256':sha_file(signed),'size':len(new)},'ops':ops}
  raw=json.dumps(patch,separators=(',',':')).encode();encoded=base64.b64encode(gzip.compress(raw,compresslevel=9,mtime=0)).decode();Path(destination).write_text(encoded+'\n')
  return {'operations':len(ops),'copied_bytes':copied,'output_bytes':len(new),'patch_ascii_bytes':len(encoded),'patch_sha256':hashlib.sha256(encoded.encode()).hexdigest(),'output':patch['output']}
def read_patch(p):
 compressed=base64.b64decode(Path(p).read_text(),validate=False)
 with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as f:raw=f.read(8*1024*1024+1)
 if len(raw)>8*1024*1024:raise ValueError('Patch exceeds limit')
 d=json.loads(raw)
 if d.get('schema')!=1 or d['base']['sha256']!=BASE_SHA or d['base']['url']!=BASE_URL or d['output']['name']!=ASSET:raise ValueError('Patch identity mismatch')
 if not 0<d['output']['size']<350000000 or len(d['ops'])>10000:raise ValueError('Patch bounds invalid')
 return d
def apply(baseline,patch,destination):
 p=read_patch(patch);out=Path(destination)
 if sha_file(baseline)!=p['base']['sha256'] or Path(baseline).stat().st_size!=p['base']['size']:raise ValueError('Baseline mismatch')
 if out.exists():raise ValueError('Output already exists')
 try:
  with open(baseline,'rb') as bf,out.open('xb') as target:
   total=0
   for op in p['ops']:
    if op[0]==0 and len(op)==3 and type(op[1]) is int and type(op[2]) is int and op[1]>=0 and op[2]>0 and op[1]+op[2]<=p['base']['size']:
     bf.seek(op[1]);left=op[2]
     while left:
      block=bf.read(min(left,1048576))
      if not block:raise ValueError('Truncated baseline')
      target.write(block);total+=len(block);left-=len(block)
    elif op[0]==1 and len(op)==2:
     block=base64.b64decode(op[1],validate=True);target.write(block);total+=len(block)
    else:raise ValueError('Invalid patch operation')
    if total>p['output']['size']:raise ValueError('Output bounds exceeded')
  if out.stat().st_size!=p['output']['size'] or sha_file(out)!=p['output']['sha256']:raise ValueError('Signed artifact identity mismatch')
 except BaseException:
  out.unlink(missing_ok=True);raise
 return p['output']
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['generate','apply']);parser.add_argument('baseline');parser.add_argument('input');parser.add_argument('output');a=parser.parse_args()
 print(json.dumps(generate(a.baseline,a.input,a.output) if a.mode=='generate' else apply(a.baseline,a.input,a.output),sort_keys=True))
