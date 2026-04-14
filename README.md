# firewall-tool（fwctl）

以 `firewall-cmd`（線上）／`firewall-offline-cmd`（`--offline`）包一層的 firewalld 查詢／管理 CLI。

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

若出現 **Authorization failed**／**polkit** 相關訊息，代表 PolicyKit 不讓目前使用者連到 `firewalld`，需用 **root** 跑 `fwctl`。

`sudo` 預設會**重設 PATH**，常常找不到裝在 venv／家目錄下的 `fwctl`，因而出現 `sudo: fwctl: command not found`。請在**一般使用者** shell 先解析路徑再給 sudo：

```bash
sudo "$(command -v fwctl)" status
# 或
sudo /path/to/firewallTool/.venv/bin/fwctl status
```

也可改用 `sudo env "PATH=$PATH" fwctl status`（視 `sudoers` 是否允許保留 PATH）。長期作法是把 `fwctl` 裝進系統路徑（例如 `/usr/local/bin`）或寫一條 root 也找得到的 wrapper。

常用指令（多數變更需 **root**；變更類可用 `--dry-run` 預覽、`--yes` 略過確認）：

| 目的 | 範例 |
|------|------|
| 總覽狀態 | `fwctl status` |
| 含所有 zone 詳情 | `fwctl status --all-zones` |
| Zone 列表／單一 zone | `fwctl zone list` · `fwctl zone show public` |
| 服務／埠列表 | `fwctl service list` · `fwctl port list` |
| 加服務（永久＋指定 zone） | `fwctl service add http --zone public --permanent --yes` |
| Rich rules | `fwctl rule list` · `fwctl rule add --rule 'rule family=...'` |
| ipset 列表／詳情 | `fwctl ipset list` · `fwctl ipset show MYSET`（可加 `--permanent`） |
| direct 規則 | `fwctl direct rules` · 另可 `direct chains`、`direct passthroughs` |
| 重載 runtime | `fwctl reload --yes` |
| 緊急 panic | `fwctl panic on` · `fwctl panic off` |

`--permanent`（**僅線上模式**）只影響「寫入永久設定檔」與 `list` 的資料來源；若要讓 runtime 與永久設定一致，變更後需執行 `fwctl reload`（或 `firewall-cmd --reload`）。

### `--offline`（`firewall-offline-cmd`）

當 **`firewalld` 未執行**或要在 **chroot／映像建置** 等情境直接改磁碟上的設定時，在**最前面**加上 `--offline`（必須寫在子命令之前）：

```bash
fwctl --offline status
fwctl --offline zone show public
fwctl --offline service add http --zone public --yes   # 仍可加 --permanent，會自動略過
```

離線模式下：**沒有 runtime／D-Bus**，`status` 不會顯示 daemon `--state` 與 runtime 的 active zones；`reload` 與 `panic` 會拒絕執行（僅線上有效）。`run_firewall_cmd` 會自動從參數列**移除 `--permanent`**，以符合多數版本 `firewall-offline-cmd` 的參數行為。
