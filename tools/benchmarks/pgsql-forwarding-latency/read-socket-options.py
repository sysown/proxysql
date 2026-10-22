from pathlib import Path
import os,sys,json,socket,ctypes
pid=int(sys.argv[1]);port=int(sys.argv[2]);libc=ctypes.CDLL(None,use_errno=True)
pidfd=os.pidfd_open(pid);rows=[];errors=[]
try:
 for entry in Path(f'/proc/{pid}/fd').iterdir():
  try:
   if not os.readlink(entry).startswith('socket:'):continue
   fd=libc.syscall(438,pidfd,int(entry.name),0)
   if fd<0:errors.append(dict(fd=int(entry.name),errno=ctypes.get_errno()));continue
   with socket.socket(fileno=fd) as s:
    if s.family not in [socket.AF_INET,socket.AF_INET6]:continue
    try:local=s.getsockname();peer=s.getpeername()
    except OSError:continue
    role='frontend' if local[1]==port else ('backend' if peer[1]==5432 else None)
    if role:rows.append(dict(fd=int(entry.name),role=role,local=local,peer=peer,tcp_nodelay=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY),tcp_cork=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_CORK)))
  except FileNotFoundError:pass
finally:os.close(pidfd)
print(json.dumps(dict(pid=pid,port=port,sockets=rows,errors=errors),indent=2))
assert not errors,errors
assert len([x for x in rows if x['role']=='frontend'])==1,rows
assert len([x for x in rows if x['role']=='backend'])==64,len(rows)
assert all(x['tcp_nodelay']==1 and x['tcp_cork']==0 for x in rows),rows
