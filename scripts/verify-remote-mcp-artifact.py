"""Production-binary checks using ephemeral synthetic profiles and signing keys."""
import base64, hashlib, json, os, pathlib, queue, threading, socket, subprocess, sys, tempfile, time, urllib.request, urllib.error
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
binary=pathlib.Path(sys.argv[1]).resolve()
cli=pathlib.Path(sys.argv[2]).resolve()

def enc(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def integer(n): return enc(n.to_bytes((n.bit_length()+7)//8, 'big'))
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
pub=key.public_key().public_numbers()
def token(**overrides):
 claims=dict(iss='https://issuer.example.test',aud='https://dbx.example.test/mcp',sub='owner',scope='dbx:mcp',exp=int(time.time())+120,nbf=int(time.time())-1)
 claims.update(overrides)
 body='.'.join(enc(json.dumps(v,separators=(',',':')).encode()) for v in [dict(alg='RS256',typ='at+jwt',kid='ephemeral-test'),claims])
 return body+'.'+enc(key.sign(body.encode(),padding.PKCS1v15(),hashes.SHA256()))
with tempfile.TemporaryDirectory(prefix='dbx-release-synthetic-') as temporary:
 root=pathlib.Path(temporary)
 env={k:v for k,v in os.environ.items() if not k.startswith('DBX_')}
 env.update(HOME=str(root/'home'),USERPROFILE=str(root/'home'),APPDATA=str(root/'config'),LOCALAPPDATA=str(root/'config'),XDG_CONFIG_HOME=str(root/'config'),DBX_DATA_DIR=str(root/'data'),RUST_LOG='warn')
 for path in [root/'home',root/'config',root/'data']: path.mkdir(mode=0o700)
 fixture_key=root/'fixture-data-key'
 fixture_key.write_text(os.urandom(32).hex())
 fixture_key.chmod(0o600)
 env['DBX_SECRET_KEY_FILE']=str(fixture_key)
 jwks=dict(keys=[dict(kty='RSA',alg='RS256',use='sig',kid='ephemeral-test',n=integer(pub.n),e=integer(pub.e))])
 (root/'jwks.json').write_text(json.dumps(jwks))
 config=dict(issuer='https://issuer.example.test',resource='https://dbx.example.test/mcp',jwks_file='jwks.json',allowed_subjects=['owner','second-owner'],required_scope='dbx:mcp')
 (root/'oauth.json').write_text(json.dumps(config))
 env['DBX_MCP_OAUTH_CONFIG_FILE']=str(root/'oauth.json')
 with socket.socket() as s: s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
 process=subprocess.Popen([str(binary),'--http','--http-port',str(port)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 def request(method='POST',body=None,auth=None,session=None,path='/mcp',extra=None):
  headers={'Accept':'application/json, text/event-stream','Content-Type':'application/json'}
  if auth: headers['Authorization']='Bearer '+auth
  if session: headers['Mcp-Session-Id']=session
  if extra: headers.update(extra)
  data=None if body is None else body if isinstance(body,bytes) else json.dumps(body).encode()
  req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=data,headers=headers,method=method)
  try:
   with opener.open(req,timeout=10) as r: return r.status,dict(r.headers),r.read()
  except urllib.error.HTTPError as e: return e.code,dict(e.headers),e.read()
 def rpc(body,auth,session=None):
  status,headers,data=request(body=body,auth=auth,session=session)
  assert 200 <= status < 300, f'RPC HTTP status {status}'
  if data.startswith(b'event:') or b'\ndata:' in data or data.startswith(b'data:'):
   values=[json.loads(line[5:].strip()) for line in data.splitlines() if line.startswith(b'data:') and line[5:].strip()]
   value=next(v for v in values if v.get('id')==body.get('id'))
  else: value=json.loads(data)
  return headers,value
 report={}
 try:
  deadline=time.monotonic()+20
  while True:
   try:
    status,headers,data=request('GET',path='/healthz')
    if status==200: break
   except urllib.error.URLError: pass
   if process.poll() is not None: raise RuntimeError('synthetic server exited before health')
   if time.monotonic()>deadline: raise RuntimeError('synthetic server start timed out')
   time.sleep(.1)
  status,headers,data=request('GET',path='/.well-known/oauth-protected-resource/mcp')
  assert status==200 and json.loads(data)['resource']==config['resource']
  report['resource_metadata']=True
  for name,tok,expected in [('missing',None,401),('wrong','synthetic-invalid',401),('expired',token(exp=int(time.time())-1),401),('audience',token(aud='https://other.example.test/mcp'),401),('issuer',token(iss='https://other.example.test'),401),('subject',token(sub='uninvited'),403),('scope',token(scope='openid'),403)]:
   status,headers,data=request(body={},auth=tok)
   assert status==expected, f'{name}: expected {expected}, got {status}'
   report['reject_'+name]=True
  auth=token()
  headers,init=rpc(dict(jsonrpc='2.0',id=1,method='initialize',params=dict(protocolVersion='2025-06-18',capabilities={},clientInfo=dict(name='synthetic-release-smoke',version='1'))),auth)
  session=next(v for k,v in headers.items() if k.lower()=='mcp-session-id')
  assert 'result' in init
  assert request(body=dict(jsonrpc='2.0',method='notifications/initialized'),auth=auth,session=session)[0]==202
  _,listed=rpc(dict(jsonrpc='2.0',id=2,method='tools/list',params={}),auth,session)
  tools={t['name'] for t in listed['result']['tools']}
  assert {'dbx_list_connections','dbx_import_connections'} <= tools
  _,called=rpc(dict(jsonrpc='2.0',id=3,method='tools/call',params=dict(name='dbx_list_connections',arguments={})),auth,session)
  assert not called.get('result',{}).get('isError',False)
  report['authenticated_initialize_list_call']=True;report['tool_count']=len(tools)
  assert request(body={},auth=token(sub='second-owner'),session=session)[0]==403
  assert request(body={},auth=auth,session=session,extra={'Origin':'https://evil.example.test'})[0]==403
  assert request(body=b'x'*(1024*1024+1),auth=auth)[0]==413
  report['session_origin_body_boundaries']=True
  assert request('DELETE',auth=auth,session=session)[0]==202
  assert request(body={},auth=auth,session=session)[0]==404
  report['delete_invalidates_session']=True
 finally:
  if os.name=='nt': process.terminate()
  else: process.send_signal(2)
  try: stdout,stderr=process.communicate(timeout=15)
  except subprocess.TimeoutExpired: process.kill(); stdout,stderr=process.communicate();raise
  assert auth.encode() not in stderr if 'auth' in locals() else True
  assert b'BEGIN PRIVATE KEY' not in stderr
  if os.name!='nt': assert process.returncode==0, 'unclean HTTP shutdown'
  report['http_shutdown']='terminated isolated test process after DELETE' if os.name=='nt' else 'graceful SIGINT'
 # CLI and stdio operate only on the same ephemeral empty profile.
 env.pop('DBX_MCP_OAUTH_CONFIG_FILE',None)
 output=subprocess.run([str(cli),'connections','list','--json'],env=env,capture_output=True,check=True,timeout=15)
 assert json.loads(output.stdout)=={"connections": []}
 report['cli_empty_profile']=True
 process=subprocess.Popen([str(binary)],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 replies=queue.Queue()
 def read_replies():
  for line in process.stdout: replies.put(line)
 reader=threading.Thread(target=read_replies,daemon=True);reader.start()
 def exchange(value):
  process.stdin.write(json.dumps(value)+'\n');process.stdin.flush()
  if 'id' not in value:return None
  return json.loads(replies.get(timeout=15))
 assert 'result' in exchange(dict(jsonrpc='2.0',id=10,method='initialize',params=dict(protocolVersion='2025-06-18',capabilities={},clientInfo=dict(name='synthetic-stdio-smoke',version='1'))))
 exchange(dict(jsonrpc='2.0',method='notifications/initialized'))
 assert 'result' in exchange(dict(jsonrpc='2.0',id=11,method='tools/list',params={}))
 process.stdin.close();process.wait(timeout=15)
 assert process.returncode==0
 report['stdio_compatible']=True
 report['platform']=sys.platform
 report['fixture_key']='ephemeral explicit key file; real keyrings unused'
 report['binary_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [binary,cli]}
 print(json.dumps(report,sort_keys=True,indent=2))
