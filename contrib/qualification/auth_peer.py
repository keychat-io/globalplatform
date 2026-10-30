"""Exercise the SDK against CardPress's independent pyca peer; synthetic keys only."""
import importlib.util,pathlib,subprocess,json,argparse
parser=argparse.ArgumentParser()
parser.add_argument("--peer",type=pathlib.Path,required=True)
parser.add_argument("--probe",type=pathlib.Path,required=True)
parser.add_argument("--require-s16",action="store_true")
args=parser.parse_args()
spec=importlib.util.spec_from_file_location('peer',args.peer)
peer=importlib.util.module_from_spec(spec);spec.loader.exec_module(peer)
results=[]
for name,protocol,option in [('scp02',2,0x55),('scp03',3,0),('scp03-pseudo',3,0x10),('scp03-s16',3,1),('scp03-s16-pseudo',3,0x11)]:
 card=peer.Card(name);failure=None;calls=0;challenge_bytes=None
 p=subprocess.Popen([str(args.probe.resolve()),str(protocol),str(option)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 result=None
 for line in p.stdout:
  if line.startswith('RESULT '):result=line.strip();continue
  if not line.startswith('APDU '):continue
  calls+=1
  try:
   command=bytes.fromhex(line[5:].strip())
   if len(command)>4 and command[1]==0x50:challenge_bytes=command[4]
   response=card.transmit(command)
   reply=response['data']+format(response['sw'],'04x')
  except Exception as e:
   failure=type(e).__name__+': '+str(e);reply='!'
  p.stdin.write(reply+'\n');p.stdin.flush()
 p.stdin.close();stderr=p.stderr.read();code=p.wait()
 results.append(dict(protocol=name,calls=calls,initialize_challenge_bytes=challenge_bytes,result=result,peer_failure=failure,exit=code,stderr=stderr))
print(json.dumps(results,indent=2))

required=results if args.require_s16 else results[:3]
raise SystemExit(0 if all(r["exit"]==0 and r["result"]=="RESULT registry 0 count=1" and r["peer_failure"] is None for r in required) else 1)
