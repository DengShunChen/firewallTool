# firewall-tool（fwctl）

以 `firewall-cmd`（線上）／`firewall-offline-cmd`（`--offline`）包一層的 firewalld 查詢／管理 CLI。

**完整教學（firewalld 邏輯、sudo／PATH、direct 防呆步驟、offline、疑難排解）請見：[docs/使用教學.md](docs/使用教學.md)。**

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
| ipset 列表／詳情／增刪條目 | `fwctl ipset list` · `fwctl ipset show MYSET` · `add-entry` / `remove-entry`；不熟可用 **`ipset wizard-add`** / **`wizard-remove`**（見教學 §6.5） |
| direct 規則 | `fwctl direct rules` · 另可 `direct chains`、`direct passthroughs` |
| direct 新增／刪除 | `direct add` / `direct remove`（見教學）；不熟可用 **`direct wizard-add`** / **`wizard-remove`** |
| 重載 runtime | `fwctl reload --yes` |
| 緊急 panic | `fwctl panic on` · `fwctl panic off` |

`--permanent`（**僅線上模式**）只影響「寫入永久設定檔」與 `list` 的資料來源；若要讓 runtime 與永久設定一致，變更後需執行 `fwctl reload`（或 `firewall-cmd --reload`）。

### 進階：`--offline`、`direct add/remove`

離線模式、`direct` 防呆與「如何從 `direct rules` 剪下正確的 `--rule`」等，請改讀教學文件 **[docs/使用教學.md](docs/使用教學.md)** 第 7～9 節，避免與 README 重複維護兩份內容。
