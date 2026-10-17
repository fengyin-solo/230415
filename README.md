# 设备出厂放行工位：许可证封套核验

这台工位在设备下线前刷厂商签发的许可证封套，核验通过才允许封箱。本仓库是这条工位的
核验脚本加它的一整套验收材料。

## 目录

```
instruction.md            给 agent 看的题面（唯一契约）
task.toml                 运行环境与超时配置
environment/Dockerfile    离线镜像定义（基础镜像按 digest 固定，pytest 从本地 wheel 安装）
environment/app/          现场那支有缺陷的核验脚本（候选程序的起点）
environment/data/         随题交付的演练输入：公钥、四份封套、当天的吊销名单
environment/wheels/       离线依赖
environment/generate_data.py  演练数据的生成脚本（无随机源，重复运行逐字节一致）
solution/                 参考解与安装入口
tests/                    验收脚本（pytest）与 reward 写入入口
```

## 怎么跑

```bash
# 环境自检
python3 environment/generate_data.py --out /tmp/data-check     # 确定性复算
python3 -m pytest tests/test_outputs.py                        # 需要 TASK_APP / TASK_DATA_DIR
```

验收入口是 `tests/test.sh`：先写 `reward=0`，再跑 pytest，只有整套断言通过才写 `1.000`，
并把完整日志同时留在 `/logs/verifier/test-log.txt`。

## 输入摘要

演练输入（`environment/data/` 下 7 个文件的逐文件 sha256 拼接后再取 sha256）：

```
fbaab3ed367edff12c075c92b2384eabfad8302ddeca8655827c24312c2f1110
```

复算命令：

```bash
python3 - <<'PY'
import hashlib, pathlib
files = sorted(p for p in pathlib.Path("environment/data").rglob("*") if p.is_file())
rows = [f"{p.relative_to('environment/data')} {hashlib.sha256(p.read_bytes()).hexdigest()}" for p in files]
print(hashlib.sha256("\n".join(rows).encode()).hexdigest())
PY
```

题目包整体的 Harbor dirhash（`dirhash(<本目录>, "sha256")`）由验收流程每次重算并记录在工作区
的 manifest 里；它覆盖本目录全部文件，因此**改动任何一个交付文件都必须重跑 Oracle/NOP 与反证**。

## 回归与回滚

1. 改动题目内容后重跑参考解与空跑两条基线：`oracle` 必须 `reward=1.0`、`nop` 必须 `reward=0.0`；
2. 重新生成覆盖矩阵与逐项反证，确认每条反证仍被杀死；
3. 重新计算 `tests/test.sh` 的执行位（必须 `0755`）与 reward 文件权限（运行时 `0444`）；
4. 需要回退时按提交历史回滚到上一个已验证的 commit，再重跑上面的 1–3 步；不要只改单个文件后直接复测。

## 说明

- 这台工位只处理本地文件，不访问网络。
- `environment/data/` 里的封套与密钥都是演练数据，不含任何真实客户信息。
