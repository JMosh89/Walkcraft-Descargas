#!/usr/bin/env python3
"""Publish an exact already-signed artifact. Does not read or use signing keys."""
import base64,datetime,hashlib,importlib.util,json,os,subprocess,time,urllib.request
from pathlib import Path
REPO='JMosh89/Walkcraft-Descargas';TAG='v0.8.2';ROOT='release-data/v0.8.2';ASSET='Walkcraft-Android-0.8.2-Normal.apk'
spec=importlib.util.spec_from_file_location('delta272','delta.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
phase='initialization';result={'status':'FAILED','tag':TAG,'repository':REPO}
def gh(args,check=True):
 p=subprocess.run(['gh',*args],capture_output=True,text=True)
 if check and p.returncode:raise RuntimeError('GitHub operation failed: '+p.stderr.strip()[:800])
 return p
def api(path):return json.loads(gh(['api',path]).stdout)
def mutate(method,path,data):
 Path('request.json').write_text(json.dumps(data));return json.loads(gh(['api','--method',method,path,'--input','request.json']).stdout)
def download(url,path):
 with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Walkcraft-release-verifier/0.8.2'}),timeout=120) as src,open(path,'wb') as target:
  if src.status!=200:raise RuntimeError('Download did not return200')
  for block in iter(lambda:src.read(1048576),b''):target.write(block)
def record(data):
 name=ROOT+'/result.json';p=gh(['api','repos/'+REPO+'/contents/'+name],False);body={'message':'Record verified Walkcraft0.8.2 publication','content':base64.b64encode((json.dumps(data,indent=2)+'\n').encode()).decode(),'branch':'main'}
 if p.returncode==0:body['sha']=json.loads(p.stdout)['sha']
 mutate('PUT','repos/'+REPO+'/contents/'+name,body)
try:
 start=json.loads(Path('start.json').read_text());patch=D.read_patch('patch.b64')
 if os.environ.get('GITHUB_REPOSITORY')!=REPO or start['tag']!=TAG or start['output']!=patch['output']:raise RuntimeError('Release identity mismatch')
 if hashlib.sha256(Path('patch.b64').read_text().strip().encode()).hexdigest()!=start['patch_sha256']:raise RuntimeError('Patch transfer mismatch')
 phase='baseline-download';download(D.BASE_URL,'baseline.apk')
 phase='artifact-reconstruction';D.apply('baseline.apk','patch.b64',ASSET)
 if D.sha_file(ASSET)!=start['output']['sha256']:raise RuntimeError('Artifact hash mismatch')
 notes=Path('notes.md').read_text();marker='APK SHA-256: '+start['output']['sha256'];body=notes+'\n\n'+marker+'\n'
 phase='draft-creation';endpoint='repos/'+REPO+'/releases/tags/'+TAG;p=gh(['api',endpoint],False)
 if p.returncode==0:
  release=json.loads(p.stdout)
  if marker not in release.get('body',''):raise RuntimeError('Existing release belongs to different artifact; refusing overwrite')
 elif 'HTTP 404' in p.stderr:
  release=mutate('POST','repos/'+REPO+'/releases',{'tag_name':TAG,'target_commitish':os.environ['GITHUB_SHA'],'name':'Walkcraft0.8.2 — Ascensión y Super Límite','body':body,'draft':True,'prerelease':False})
 else:raise RuntimeError('Unable to inspect destination release')
 phase='asset-upload';matches=[a for a in release['assets'] if a['name']==ASSET]
 if len(matches)>1:raise RuntimeError('Duplicate matching release assets')
 if not matches:
  if not release['draft']:raise RuntimeError('Refusing to modify an already published release without its expected APK')
  gh(['release','upload',TAG,ASSET,'--repo',REPO])
 phase='authenticated-download-verification';Path('verify').mkdir(exist_ok=True);gh(['release','download',TAG,'--pattern',ASSET,'--dir','verify','--repo',REPO,'--clobber'])
 if D.sha_file(Path('verify')/ASSET)!=start['output']['sha256']:raise RuntimeError('Uploaded APK differs from local signed artifact')
 phase='publication';release=api(endpoint)
 if release['draft']:release=mutate('PATCH','repos/'+REPO+'/releases/'+str(release['id']),{'draft':False,'prerelease':False,'make_latest':'true'})
 phase='public-anonymous-download-verification';release=api(endpoint);asset=next(a for a in release['assets'] if a['name']==ASSET);url=asset['browser_download_url']
 for attempt in range(3):
  try:
   download(url,'public.apk')
   if D.sha_file('public.apk')!=start['output']['sha256']:raise RuntimeError('Public download hash mismatch')
   break
  except Exception:
   if attempt==2:raise
   time.sleep(3*(attempt+1))
 result={'status':'PUBLIC_DOWNLOAD_VERIFIED','repository':REPO,'tag':TAG,'release_id':release['id'],'release_url':release['html_url'],'asset_id':asset['id'],'asset_url':url,'sha256':D.sha_file('public.apk'),'size_bytes':Path('public.apk').stat().st_size,'anonymous_download_verified':True,'source_commit':os.environ['GITHUB_SHA'],'published_at':release['published_at'],'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'feed_modified':False,'signing_key_used':False}
except Exception as e:
 result.update(phase=phase,error=str(e)[:1000]);raise
finally:
 try:record(result)
 finally:print(json.dumps(result,sort_keys=True))
