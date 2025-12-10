import subprocess
import psutil
import logging
import re
import socket
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# ロギング設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SocatManager")

app = FastAPI(title="Socat Port Forward Manager")

# メモリ上でプロセスを管理する辞書
# key: pid (int), value: RuleInfo
running_processes: Dict[int, dict] = {}

class RuleRequest(BaseModel):
    local_port: int
    target_ip: str
    target_port: int
    protocol: str = "TCP"  # Default to TCP

class RuleResponse(RuleRequest):
    pid: int
    status: str

def parse_socat_args(cmdline: List[str]) -> Optional[Dict]:
    """
    Parse socat command line arguments to extract rule information.
    Expected format: ['socat', 'PROTOCOL-LISTEN:PORT,...', 'PROTOCOL:IP:PORT']
    """
    if len(cmdline) < 3:
        return None

    # Check if it is likely a socat command we manage
    if 'socat' not in cmdline[0]:
        return None

    src = cmdline[1]
    dst = cmdline[2]

    # Parse Source (Listen)
    # Regex for TCP4-LISTEN:8080,fork,reuseaddr or UDP4-LISTEN...
    listen_pattern = re.compile(r'(TCP|UDP)4-LISTEN:(\d+)')
    match_src = listen_pattern.search(src)
    if not match_src:
        return None

    protocol = match_src.group(1) # TCP or UDP
    local_port = int(match_src.group(2))

    # Parse Destination
    # Regex for TCP4:10.8.0.10:80 or UDP4...
    dst_pattern = re.compile(r'(TCP|UDP)4:([\d\.]+):(\d+)')
    match_dst = dst_pattern.search(dst)
    if not match_dst:
        return None

    # Check if protocols match (sanity check)
    if match_dst.group(1) != protocol:
        return None

    target_ip = match_dst.group(2)
    target_port = int(match_dst.group(3))

    return {
        "local_port": local_port,
        "target_ip": target_ip,
        "target_port": target_port,
        "protocol": protocol
    }

def scan_socat_processes():
    """Scan for existing socat processes and populate running_processes"""
    logger.info("Scanning for existing socat processes...")
    count = 0
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] == 'socat':
                cmdline = proc.info['cmdline']
                parsed = parse_socat_args(cmdline)
                if parsed:
                    pid = proc.info['pid']
                    if pid not in running_processes:
                        running_processes[pid] = parsed
                        logger.info(f"Discovered existing socat process PID {pid}: {parsed}")
                        count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    logger.info(f"Scan complete. Found {count} existing processes.")

def is_port_in_use(port: int, protocol: str) -> bool:
    """
    Check if the port is currently in use on the OS.
    Attempts to bind a socket to 0.0.0.0:port.
    """
    try:
        sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as s:
            # We set REUSEADDR to check if we can bind *with* reuseaddr,
            # which matches what socat does.
            # However, if an existing process (socat) is running with REUSEADDR,
            # another bind with REUSEADDR might succeed on some OSs (like Linux with SO_REUSEPORT or UDP behavior).
            # But socat uses SO_REUSEADDR.
            # In Linux, SO_REUSEADDR allows binding to a port in TIME_WAIT, but not one in LISTEN state (for TCP).
            # So if socat is listening, binding should fail even with REUSEADDR (unless it's UDP multicast/broadcast or specific OS quirks).
            # For UDP, SO_REUSEADDR allows multiple binds to the same port.
            # If we want to prevent *conflict*, we might want to check *without* REUSEADDR to be safer?
            # But socat uses it. If socat uses it, it means socat intends to allow sharing or overtaking.
            # BUT, we want to know if *another* socat is already there.
            # If socat is there (with reuseaddr), and we try to bind with reuseaddr:
            # - TCP: Fail (EADDRINUSE). Correct.
            # - UDP: Succeed. Incorrect (we don't want to double bind).

            # So for UDP, checking with REUSEADDR is bad if we want to detect duplicates.
            # But socat *uses* reuseaddr.

            # If we check WITHOUT reuseaddr:
            # - TCP with socat (reuseaddr): Fail (EADDRINUSE). Correct.
            # - UDP with socat (reuseaddr): Fail (EADDRINUSE). Correct.

            # So, checking WITHOUT reuseaddr seems to be the robust way to see if *anyone* is there.

            # But wait, if a port is in TIME_WAIT, check WITHOUT reuseaddr will fail (saying in use),
            # but socat (WITH reuseaddr) would succeed.
            # So we might report a false positive for conflict if we are too strict.

            # Let's try to mimic socat behavior?
            # If socat command is `TCP4-LISTEN:8080,fork,reuseaddr`.
            # We should probably check if we can bind WITH reuseaddr for TCP.

            # For UDP, `UDP4-LISTEN:...,reuseaddr`.
            # On Linux, SO_REUSEADDR on UDP allows multiple sockets to bind.
            # So `is_port_in_use` will return False (not in use, i.e., bind success) even if another socat is running!
            # That's a problem if we want to prevent duplicates.

            # If the user wants to "avoid port duplication", for UDP, we probably shouldn't allow multiple socats on the same port
            # unless intended.

            # So, for UDP, maybe we should check WITHOUT reuseaddr to be sure nobody is there?
            # But what if TIME_WAIT? UDP doesn't have TIME_WAIT.
            # So for UDP, check without reuseaddr.

            # For TCP, check WITH reuseaddr (to allow TIME_WAIT reuse).

            if protocol == "TCP":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind(('0.0.0.0', port))
            return False
    except OSError:
        return True

@app.on_event("startup")
async def startup_event():
    scan_socat_processes()

@app.get("/")
async def read_index():
    return FileResponse('index.html')

@app.get("/api/rules", response_model=List[RuleResponse])
async def get_rules():
    """現在稼働中の転送ルール一覧を取得し、死んでいるプロセスは掃除する"""
    active_rules = []
    dead_pids = []

    for pid, info in running_processes.items():
        if psutil.pid_exists(pid):
            try:
                proc = psutil.Process(pid)
                if proc.status() == psutil.STATUS_ZOMBIE:
                    dead_pids.append(pid)
                else:
                    active_rules.append({
                        "pid": pid,
                        "status": "Running",
                        **info
                    })
            except psutil.NoSuchProcess:
                dead_pids.append(pid)
        else:
            dead_pids.append(pid)

    for pid in dead_pids:
        del running_processes[pid]

    return active_rules

@app.post("/api/rules", response_model=RuleResponse)
async def create_rule(rule: RuleRequest):
    """新しいポートフォワーディングルールを作成（socatを起動）"""
    
    # Check internal registry first (cheap)
    for info in running_processes.values():
        if info['local_port'] == rule.local_port and info['protocol'] == rule.protocol:
            raise HTTPException(status_code=400, detail=f"{rule.protocol} Port {rule.local_port} is already being forwarded by this app.")

    # Check OS availability (robust)
    proto = rule.protocol.upper()
    if proto not in ["TCP", "UDP"]:
        raise HTTPException(status_code=400, detail="Protocol must be TCP or UDP")

    if is_port_in_use(rule.local_port, proto):
        raise HTTPException(status_code=400, detail=f"{proto} Port {rule.local_port} is already in use by another process.")

    # コマンドの構築
    cmd = [
        "socat",
        f"{proto}4-LISTEN:{rule.local_port},fork,reuseaddr",
        f"{proto}4:{rule.target_ip}:{rule.target_port}"
    ]

    try:
        # サブプロセスとして実行（バックグラウンド）
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # プロセスが即死していないか少し待って確認
        try:
            # 0.1秒待機して終了コードを確認
            outs, errs = proc.communicate(timeout=0.4)
            # もしここで例外が出なければ、プロセスは終了してしまっている
            if proc.returncode != 0:
                raise Exception(f"Socat failed to start: {errs.decode()}")
        except subprocess.TimeoutExpired:
            # タイムアウト＝プロセスは継続して実行中（成功）
            pass

        logger.info(f"Started socat PID {proc.pid}: {cmd}")

        # 管理簿に登録
        rule_info = rule.dict()
        rule_info['protocol'] = proto # Ensure uppercase
        running_processes[proc.pid] = rule_info

        return {
            "pid": proc.pid,
            "status": "Running",
            **rule_info
        }

    except Exception as e:
        logger.error(f"Error starting socat: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/rules/{pid}")
async def delete_rule(pid: int):
    """指定されたPIDのsocatプロセスを停止する"""
    if pid not in running_processes:
        raise HTTPException(status_code=404, detail="Rule not found")

    try:
        if psutil.pid_exists(pid):
            parent = psutil.Process(pid)
            # 子プロセスも含めてkillする
            for child in parent.children(recursive=True):
                child.terminate()
            parent.terminate()
            logger.info(f"Terminated socat PID {pid}")
        
        del running_processes[pid]
        return {"message": "Rule deleted successfully"}

    except Exception as e:
        logger.error(f"Error checking/killing process: {e}")
        # プロセスが見つからない場合も管理簿からは消す
        if pid in running_processes:
            del running_processes[pid]
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser(description='Socat manager')
    parser.add_argument('host', type=str)
    parser.add_argument('port', type=int)
    args = parser.parse_args()
    uvicorn.run(app=app, host=args.host, port=args.port)
