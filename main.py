import subprocess
import psutil
import logging
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
    protocol: str = "TCP"

class RuleResponse(RuleRequest):
    pid: int
    status: str

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
            # プロセスが存在しても、ゾンビ状態でないか確認
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

    # 停止したプロセスを管理簿から削除
    for pid in dead_pids:
        del running_processes[pid]

    return active_rules

@app.post("/api/rules", response_model=RuleResponse)
async def create_rule(rule: RuleRequest):
    """新しいポートフォワーディングルールを作成（socatを起動）"""
    
    # ポート重複の簡易チェック（厳密にはOSに聞くべきだが、簡易実装として管理簿を見る）
    for info in running_processes.values():
        if info['local_port'] == rule.local_port:
            raise HTTPException(status_code=400, detail=f"Port {rule.local_port} is already being forwarded by this app.")

    # コマンドの構築
    # socat TCP4-LISTEN:8080,fork,reuseaddr TCP4:10.8.0.10:80
    cmd = [
        "socat",
        f"TCP4-LISTEN:{rule.local_port},fork,reuseaddr",
        f"TCP4:{rule.target_ip}:{rule.target_port}"
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
