# MCPSafety Server - 使用说明

## 简介

MCPSafety server 是一个从JSON配置文件动态加载的多server实现，包含13个不同功能的server，共42个工具。

## 快速开始

### 1. 独立测试 MCPSafety Server

```bash
# 运行 server.py 查看所有加载的 servers
python3 experiments/attackers/mcpsafety/server.py
```

输出示例：
```
Loaded 13 servers:
  [0] date: 5 tools - Date and time utilities
  [1] weather: 2 tools - Weather information from NWS API
  [2] echo: 1 tools - Echo service for testing
  ...
  [12] google_sheets: 5 tools - Google Sheets (requires service account)

Testing date server (index 0):
  Result: {'status': 'success', 'tool': 'get_today_date', ...}
```

### 2. 在实验中使用

创建一个YAML配置文件：

```yaml
# experiments/exp_mcpsafety_test.yaml
exp_id: mcpsafety_test
output_root: results

agent:
  model: ${OPENROUTER_MODEL}
  base_url: ${OPENROUTER_BASE_URL}
  api_key_env: OPENROUTER_API_KEY

shield:
  enabled: false

runs:
  - run_id: test_date
    server_id: mcpsafety  # 使用 mcpsafety 将加载所有13个server
    query: "What is today's date?"
  
  - run_id: test_github
    server_id: mcpsafety
    query: "Search for Python repositories on GitHub"
```

运行实验：
```bash
python3 run_exp.py experiments/exp_mcpsafety_test.yaml
```

### 3. 程序化使用

```python
from run_exp import load_servers, MultiServerClient

# 方法1: 加载所有13个servers
servers = load_servers('mcpsafety')
print(f"加载了 {len(servers)} 个 servers")

# 方法2: 使用 MultiServerClient 包装
client = MultiServerClient(servers)
manifest = client.fetch_manifest()
print(f"共有 {len(manifest['tools'])} 个工具")

# 调用工具
result = client.invoke('get_today_date', {})
print(result)
```

## 13个Server清单

### 0. date (5 tools)
- `get_today_date` - 获取今天的日期
- `get_current_datetime` - 获取当前日期时间
- `get_current_datetime_utc` - 获取UTC时间
- `get_date_in_timezone` - 获取指定时区时间
- `get_timestamp` - 获取Unix时间戳

### 1. weather (2 tools)
- `get_alerts` - 获取天气警报
- `get_forecast` - 获取天气预报

### 2. echo (1 tool)
- `echo_tool` - 回显输入文本

### 3. wikipedia (1 tool)
- `search` - 搜索Wikipedia

### 4. terminal (1 tool)
- `run_command` - 运行终端命令

### 5. github (5 tools)
- `get_me` - 获取当前用户信息
- `search_repositories` - 搜索仓库
- `get_file_contents` - 获取文件内容
- `create_or_update_file` - 创建或更新文件
- `create_issue` - 创建issue

### 6. yahoo_finance (4 tools)
- `get_stock_info` - 获取股票信息
- `get_yahoo_finance_news` - 获取股票新闻
- `get_historical_stock_prices` - 获取历史股价
- `get_stock_alert` - 设置股价警报

### 7. playwright (5 tools)
- `playwright_navigate` - 导航到URL
- `playwright_screenshot` - 截图
- `playwright_click` - 点击元素
- `playwright_fill` - 填充表单
- `playwright_evaluate` - 执行JavaScript

### 8. chroma (5 tools)
- `chroma_list_collections` - 列出集合
- `chroma_create_collection` - 创建集合
- `chroma_add_documents` - 添加文档
- `chroma_query_documents` - 查询文档
- `chroma_delete_collection` - 删除集合

### 9. url_fetch (2 tools)
- `fetch_url` - 获取URL内容
- `fetch_json` - 获取并解析JSON

### 10. google_search (1 tool)
- `search` - Google搜索 (需要API key)

### 11. google_maps (5 tools)
- `maps_geocode` - 地址转坐标
- `maps_reverse_geocode` - 坐标转地址
- `maps_search_places` - 搜索地点
- `maps_directions` - 获取路线
- `maps_distance_matrix` - 计算距离矩阵

### 12. google_sheets (5 tools)
- `get_sheet_data` - 获取表格数据
- `update_cells` - 更新单元格
- `list_sheets` - 列出所有sheet
- `create_spreadsheet` - 创建新表格
- `list_spreadsheets` - 列出所有表格

## 高级用法

### 只加载特定Server

如果你想只使用某个特定的server，可以在 `mcpsafety/server.py` 中使用：

```python
from experiments.attackers.mcpsafety.server import build_single_server

# 只加载 date server
date_server = build_single_server("date")

# 或者按索引加载
from experiments.attackers.mcpsafety.server import build_server_by_index
github_server = build_server_by_index(5)  # github
```

### 修改Server配置

编辑 `experiments/attackers/json_assets/mcpsafety_tools.json` 可以：
- 添加新的工具
- 修改工具描述和参数
- 添加新的server
- 修改server顺序

修改后无需更改代码，重新运行即可生效。

### 实现真实的工具逻辑

当前 `DynamicServer.invoke()` 返回mock数据。要实现真实功能：

1. 创建 `DynamicServer` 的子类
2. 重写 `invoke()` 方法
3. 在 `server.py` 中使用子类

示例：
```python
class RealDateServer(DynamicServer):
    def invoke(self, tool_name: str, args: dict) -> Any:
        if tool_name == "get_today_date":
            from datetime import datetime
            return datetime.now().strftime("%Y-%m-%d")
        # ... 其他工具实现
```

## 架构说明

```
mcpsafety/server.py (入口)
    ↓
ServerBuilder (加载器)
    ↓
mcpsafety_tools.json (配置)
    ↓
DynamicServer × 13 (server实例)
    ↓
MultiServerClient (统一接口)
    ↓
MCPShield/MCPClient (shield层)
    ↓
MainAgent (LLM agent)
```

## 注意事项

1. **API Keys**: google_search, google_maps, google_sheets 需要相应的API keys
2. **Mock数据**: 默认实现返回mock数据，实际场景需要实现真实逻辑
3. **工具命名**: 当前工具名不带前缀，未来可能添加命名空间避免冲突
4. **性能**: 加载13个server时会合并42个工具，首次调用会有缓存开销

## 问题排查

### Server加载失败
```bash
# 检查JSON文件是否存在
ls -l experiments/attackers/json_assets/mcpsafety_tools.json

# 检查JSON格式是否正确
python3 -c "import json; json.load(open('experiments/attackers/json_assets/mcpsafety_tools.json'))"
```

### 工具调用失败
```python
# 检查工具是否存在
from run_exp import load_servers, MultiServerClient
servers = load_servers('mcpsafety')
client = MultiServerClient(servers)
manifest = client.fetch_manifest()
tool_names = [t['name'] for t in manifest['tools']]
print(tool_names)
```

## 相关文档

- [MCPSAFETY_IMPLEMENTATION.md](MCPSAFETY_IMPLEMENTATION.md) - 详细的实现方案文档
- [experiments/attackers/utils/loader.py](experiments/attackers/utils/loader.py) - 基类实现
- [run_exp.py](run_exp.py) - 实验运行框架
