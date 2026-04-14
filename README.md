# firewall-tool（fwctl）

以 `firewall-cmd` 包一層的 firewalld 查詢／管理 CLI。

## 開發環境（uv）

在此環境使用 **uv** 前，請先載入代理設定：

```bash
source ~/.proxy
```

或直接使用專案腳本（會自動 `source ~/.proxy` 再呼叫 `uv`）：

```bash
chmod +x scripts/uv   # 只需做一次
./scripts/uv sync --extra dev
./scripts/uv run pytest
./scripts/uv run fwctl -- --help
```

若未使用 `scripts/uv`，請記得在每次開新 shell 後先手動 `source ~/.proxy`，再執行 `uv sync`、`uv lock` 等指令。

## 安裝與使用（目標機器需已安裝 firewalld）

在專案目錄：

```bash
./scripts/uv sync                    # 建立 .venv 並安裝本套件（可編輯）
./scripts/uv run fwctl -- --help    # 直接跑 CLI，無須另外 pip install
```

若要把 `fwctl` 裝進目前 Python 環境的 PATH：

```bash
./scripts/uv pip install -e .
```

常用指令（多數變更需 **root**；變更類可用 `--dry-run` 預覽、`--yes` 略過確認）：

| 目的 | 範例 |
|------|------|
| 總覽狀態 | `fwctl status` |
| 含所有 zone 詳情 | `fwctl status --all-zones` |
| Zone 列表／單一 zone | `fwctl zone list` · `fwctl zone show public` |
| 服務／埠列表 | `fwctl service list` · `fwctl port list` |
| 加服務（永久＋指定 zone） | `fwctl service add http --zone public --permanent --yes` |
| Rich rules | `fwctl rule list` · `fwctl rule add --rule 'rule family=...'` |
| 重載 runtime | `fwctl reload --yes` |
| 緊急 panic | `fwctl panic on` · `fwctl panic off` |

`--permanent` 只寫入永久設定；若要讓 runtime 與之一致，變更後需執行 `fwctl reload`（或 `firewall-cmd --reload`）。

本工具僅包裝 **`firewall-cmd`**，不處理 daemon 未啟動時的離線編輯；該情境請直接用系統提供的工具或先啟動 `firewalld`。
