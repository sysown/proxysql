"""Aggregate probes on existing binaries; never edit/build the product."""
from pathlib import Path
import json, os, re, signal, subprocess, time


class TLSCounter:
    def __init__(self, out, pid, binary, frontend_port):
        self.out, self.pid = out, pid
        self.proc = None
        self.stdout = self.stderr = None
        threads = []
        for p in Path(f'/proc/{pid}/task').iterdir():
            s = (p/'stat').read_text().rsplit(')', 1)[1].split()
            threads.append(dict(tid=int(p.name), ticks=int(s[11])+int(s[12]), comm=(p/'comm').read_text().strip()))
        self.worker = max(threads, key=lambda x: x['ticks'])['tid']
        (out/'threads.json').write_text(json.dumps(dict(worker=self.worker, threads=threads), indent=2))
        symbols = {}
        for line in subprocess.check_output(['nm', '-S', '-n', str(binary)], text=True).splitlines():
            parts = line.split()
            if len(parts) == 4 and parts[2] in ['T', 't']:
                symbols[parts[3]] = (int(parts[0], 16), int(parts[1], 16))
        def symbol(fragment):
            found = [n for n in symbols if fragment in n and 'PgSQL_' in n and '.cold' not in n and '.localalias' not in n]
            assert len(found) == 1, (fragment, found)
            return found[0]
        maps = Path(f'/proc/{pid}/maps').read_text()
        (out/'maps.txt').write_text(maps)
        bases = {int(p[0].split('-')[0], 16)-int(p[2], 16) for l in maps.splitlines()
                 if len(p := l.split()) >= 6 and p[-1] == str(binary)}
        # ELF LOAD alignment can produce a second apparent base in the last mapping.
        base = min(bases)
        def address_test(fragments):
            tests = []
            for fragment in fragments:
                name = symbol(fragment); start, size = symbols[name]
                tests.append(f'($caller >= {base+start} && $caller < {base+start+size})')
            return ' || '.join(tests)
        back = address_test(['native_recv_into_framerEv', 'native_flush_outbufEv', 'native_ssl_pump_wbio_to_fd'])
        front = address_test(['read_from_netEv', 'write_to_netEv', 'data_in_rbioEv'])
        classify = f'$caller = *(uint64*)uptr(reg("sp")); $side = 0; if ({back}) {{ $side = 2; }} else if ({front}) {{ $side = 1; }}'
        sockets = {}
        for family in ['tcp', 'tcp6']:
            for line in Path(f'/proc/{pid}/net/{family}').read_text().splitlines()[1:]:
                p = line.split()
                local, remote = int(p[1].split(':')[1], 16), int(p[2].split(':')[1], 16)
                if p[3] == '01':
                    if local == int(frontend_port): sockets[p[9]] = 1
                    elif remote == 5432: sockets[p[9]] = 2
        fd_roles = {}
        for path in Path(f'/proc/{pid}/fd').iterdir():
            try: target = os.readlink(path)
            except FileNotFoundError: continue
            if target.startswith('socket:[') and target[8:-1] in sockets:
                fd_roles[int(path.name)] = sockets[target[8:-1]]
        assert list(fd_roles.values()).count(1) == 500, fd_roles
        assert list(fd_roles.values()).count(2) == 10, fd_roles
        (out/'fd-roles.json').write_text(json.dumps(fd_roles, indent=2))
        # Capture exact socket roles once, after setup; no FD may be recreated
        # inside the counting window. Pipes and other descriptors remain zero.
        init = ' '.join(f'@fd_role[{fd}] = {role};' for fd, role in fd_roles.items())
        self.control_pid = os.getpid()
        enabled = f'tid == {self.worker} && @enabled'
        code = [f'BEGIN {{ {init} printf("READY\\n"); }}',
                f'tracepoint:syscalls:sys_enter_kill /pid == {self.control_pid} && args->pid == {pid} && args->sig == 0/ {{ @enabled = !@enabled; @gate_count = count(); if (@enabled) {{ @start_ns = nsecs; }} else {{ @stop_ns = nsecs; }} }}']
        def probe(name, body, ret=False):
            assert name in symbols, name
            prefix = 'uretprobe' if ret else 'uprobe'
            code.append(f'{prefix}:{binary}:{name} /{enabled}/ {{ {body} }}')
        code.append(f'uprobe:{binary}:SSL_is_init_finished /tid == {self.worker}/ {{ @observed_tls_checks = count(); if (@enabled) {{ @calls["SSL_is_init_finished", 0] = count(); @callers[*(uint64*)uptr(reg("sp")) - {base}] = count(); }} }}')
        code.append('END { clear(@enabled); clear(@fd_role); }')
        # Numeric metric IDs avoid a bpftrace 0.17/LLVM14 verifier failure with
        # unaligned stores in composite map keys containing string literals.
        names = {}
        def numeric_metric(match):
            name = match[2]
            if name not in names: names[name] = len(names)+1
            return match[1] + str(names[name]) + ','
        program = re.sub(r'(@(?:calls|returns|bytes|requested_bytes)\[)"([^"]+)",', numeric_metric, '\n'.join(code)+'\n')
        self.metric_names={v:k for k,v in names.items()}
        (out/'metric-names.json').write_text(json.dumps(self.metric_names,indent=2))
        path = out/'counter.bt'; path.write_text(program)
        (out/'probe-metadata.json').write_text(json.dumps(dict(pid=pid, worker=self.worker, base=base, fd_roles=fd_roles, role_names={0:'unclassified/worker',1:'frontend',2:'backend'}, callsites=dict(backend=back,frontend=front), profiler='bpftrace aggregate maps, no event streaming or source timers'), indent=2))
        self.stdout = (out/'bpftrace.jsonl').open('w'); self.stderr = (out/'bpftrace.stderr').open('w')
        command = ['sudo','-n','taskset','-c','18','bpftrace','-f','json',str(path)]
        (out/'profile-command.json').write_text(json.dumps(command,indent=2))
        env = os.environ.copy(); env['BPFTRACE_MAP_KEYS_MAX'] = '4096'
        self.proc = subprocess.Popen(command, stdout=self.stdout, stderr=self.stderr, env=env, start_new_session=True)
        deadline=time.monotonic()+180
        while True:
            assert self.proc.poll() is None, (out/'bpftrace.stderr').read_text()
            if 'READY' in (out/'bpftrace.jsonl').read_text(): break
            assert time.monotonic()<deadline, 'BPF compile/attach timeout'
            time.sleep(.25)

    def begin(self, snapshot):
        self.first=snapshot(); a=time.monotonic_ns(); os.kill(self.pid,0); b=time.monotonic_ns()
        self.enable=dict(before_ns=a,after_ns=b)

    def end(self, snapshot):
        a=time.monotonic_ns(); os.kill(self.pid,0); b=time.monotonic_ns(); self.disable=dict(before_ns=a,after_ns=b)
        self.last=snapshot()
        (self.out/'profile-window.json').write_text(json.dumps(dict(start=self.first,end=self.last,enable=self.enable,disable=self.disable),indent=2))

    def finish(self):
        subprocess.run(['sudo','-n','kill','-INT','--','-'+str(self.proc.pid)],check=True)
        assert self.proc.wait(timeout=30)==0, (self.out/'bpftrace.stderr').read_text()
        self.stdout.close(); self.stderr.close(); self.stdout=self.stderr=None
        maps={}
        for line in (self.out/'bpftrace.jsonl').read_text().splitlines():
            if not line.strip(): continue
            event=json.loads(line)
            if event['type']=='map': maps.update(event['data'])
        (self.out/'counter-maps.json').write_text(json.dumps(maps,indent=2))
        for key in ['@calls','@returns','@bytes','@requested_bytes']:
            maps[key]={self.metric_names[int(parts[0])]+','+','.join(parts[1:]):value for k,value in maps.get(key,{}).items() for parts in [k.split(',')]}
        assert maps['@gate_count']==2,maps
        assert maps.get('@observed_tls_checks',0)>0, 'Fresh pre-window TLS control did not exercise the attached probe'
        queries=int(self.last['Queries'])-int(self.first['Queries']); assert queries>0
        seconds=(maps['@stop_ns']-maps['@start_ns'])/1e9
        slack=(self.enable['after_ns']-self.first['before_ns'])+(self.last['after_ns']-self.disable['before_ns'])
        result=dict(queries=queries,enabled_seconds=seconds,query_rate_under_probes=queries/seconds,boundary_slack_ms=slack/1e6,boundary_slack_pct=slack/1e9/seconds*100,start=self.first,end=self.last,enable=self.enable,disable=self.disable,maps=maps)
        for key in ['@calls','@returns','@bytes','@requested_bytes']:
            result[key[1:]+'_per_query']={k:v/queries for k,v in maps.get(key,{}).items()}
        (self.out/'call-summary.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(dict(queries=queries,seconds=seconds,calls_per_query=result['calls_per_query'])),flush=True)
        return result

    def cleanup(self):
        if self.proc is not None and self.proc.poll() is None:
            subprocess.run(['sudo','-n','kill','-INT','--','-'+str(self.proc.pid)],check=False)
            try: self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                subprocess.run(['sudo','-n','kill','-TERM','--','-'+str(self.proc.pid)],check=False)
                self.proc.wait(timeout=10)
        for stream in [self.stdout,self.stderr]:
            if stream is not None: stream.close()
