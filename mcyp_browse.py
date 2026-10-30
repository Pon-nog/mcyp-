# -*- coding: utf-8 -*-
# mcyp_browse.py - 凡人小程序 浏览任务脚本 (独立版, 身份信息已内嵌)
# 任务流程: 1.点击浏览 2.等待20秒任务完成 3.返回奖励激活页点击领取, 积分到账
#
# 用法:
#   python mcyp_browse.py              # 正常执行
#   python mcyp_browse.py --debug      # 打印每次请求的 URL/Body/Headers/响应

import gzip
import hashlib
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ========== 代理支持 ==========
def get_proxy_from_env():
    """从环境变量读取代理设置
    支持格式:
      HTTP_PROXY=http://ip:port 或 http://user:pass@ip:port
      HTTPS_PROXY=http://ip:port (urllib底层HTTP代理也用于HTTPS)
    """
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    return http_proxy, https_proxy


def setup_proxy(http_proxy, https_proxy):
    """配置urllib全局代理"""
    if not http_proxy and not https_proxy:
        return False
    handlers = [urllib.request.HTTPSHandler(context=ssl_context)]
    if http_proxy or https_proxy:
        handlers.append(urllib.request.ProxyHandler({
            "http": http_proxy or https_proxy,
            "https": https_proxy or http_proxy,
        }))
    urllib.request.install_opener(urllib.request.build_opener(*handlers))
    return True


def get_proxy_from_api(api_url, api_key, timeout=15):
    """从国内代理API提取IP (支持站大爷/芝麻HTTP/青果等标准格式)
    常见返回格式:
      - TXT: 一行一个 ip:port
      - JSON: {"code":0, "data":[{"ip":"x.x.x.x","port":8080}]} 或 {"data":"ip:port"}
    返回: "http://ip:port" 或 None
    """
    if not api_url:
        return None
    try:
        import urllib.request as req
        # 构建请求URL (自动附加key参数)
        separator = "&" if "?" in api_url else "?"
        url = api_url
        if api_key and "key=" not in url and "api=" not in url:
            url = api_url + separator + "key=" + urllib.parse.quote(api_key)
        
        r = req.urlopen(url, timeout=timeout, context=ssl_context)
        raw = r.read().decode("utf-8", errors="replace").strip()
        
        # 尝试JSON解析
        try:
            data = json.loads(raw)
            # 格式1: {"data": [{"ip":"x", "port":8080}]}
            if isinstance(data, dict):
                d = data.get("data")
                if isinstance(d, list) and len(d) > 0:
                    item = d[0]
                    ip = item.get("ip") or item.get("IP")
                    port = item.get("port") or item.get("PORT")
                    if ip and port:
                        return "http://{}:{}".format(ip, port)
                # 格式2: {"data": "ip:port"}
                elif isinstance(d, str) and ":" in d:
                    return "http://" + d
                # 格式3: {"ip":"x", "port":8080}
                ip = data.get("ip") or data.get("IP")
                port = data.get("port") or data.get("PORT")
                if ip and port:
                    return "http://{}:{}".format(ip, port)
        except Exception:
            pass
        
        # 纯文本格式: 一行一个 ip:port
        if ":" in raw and "\n" not in raw and not raw.startswith("{"):
            return "http://" + raw
        # 多行取第一行
        lines = [l.strip() for l in raw.split("\n") if l.strip() and ":" in l]
        if lines:
            return "http://" + lines[0]
        
        return None
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 代理API获取失败: " + str(e))
        return None


# 全局禁用 SSL 证书验证(青龙面板等容器环境可能缺少根证书)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def parse_identity_from_raw(raw_headers):
    """从一整团抓包头中自动提取身份信息和账号备注
    支持格式: HTTP头列表(每行key: value) 或 URL编码格式
    备注格式: 在抓包字符串末尾加 #备注, 如 #3815
    返回: {"skey":..., "openid":..., "unionid":..., "uid":..., "remark":...}
    """
    result = {"skey": "", "openid": "", "unionid": "", "uid": "", "remark": ""}
    if not raw_headers:
        return result
    
    # 先提取末尾的备注 (#3815 格式)
    remark = ""
    if "#" in raw_headers:
        # 取最后一个 # 后面的内容作为备注
        parts = raw_headers.rsplit("#", 1)
        if len(parts) == 2:
            remark = parts[1].strip().split("\n")[0].strip()
            raw_headers = parts[0]
    result["remark"] = remark
    
    # 逐行解析, 支持 key: value 或 key=value 格式
    for line in raw_headers.replace("\\r\\n", "\n").replace("\\n", "\n").split("\n"):
        line = line.strip()
        if not line or line.startswith("POST ") or line.startswith("GET "):
            continue
        # 尝试 key: value 格式
        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip().lower()
            value = parts[1].strip()
        # 尝试 key=value 格式 (URL参数)
        elif "=" in line and "&" in line:
            # 处理 URL 编码的整行
            try:
                params = dict(urllib.parse.parse_qsl(line))
                for k, v in params.items():
                    k_lower = k.lower()
                    if k_lower in ("content-skey", "skey"):
                        result["skey"] = v
                    elif k_lower in ("content-openid", "openid"):
                        result["openid"] = v
                    elif k_lower in ("content-unionid", "unionid"):
                        result["unionid"] = v
                    elif k_lower in ("content-uid", "uid"):
                        result["uid"] = v
            except:
                pass
            continue
        else:
            continue
        
        # 匹配身份字段 (不区分大小写)
        if key in ("content-skey", "skey"):
            result["skey"] = value
        elif key in ("content-openid", "openid"):
            result["openid"] = value
        elif key in ("content-unionid", "unionid"):
            result["unionid"] = value
        elif key in ("content-uid", "uid"):
            result["uid"] = value
    
    return result


def load_all_accounts():
    """加载所有账号配置
    支持多账号环境变量: MINISO_RAW_HEADERS, MINISO_RAW_HEADERS_1, MINISO_RAW_HEADERS_2, ...
    每个变量值末尾可加 #备注, 如 #3815
    返回: [(identity_dict, remark), ...]
    """
    accounts = []
    # 先读取主变量
    raw = os.environ.get("MINISO_RAW_HEADERS", "")
    if raw:
        parsed = parse_identity_from_raw(raw)
        if parsed["skey"]:
            accounts.append((parsed, parsed.get("remark", "")))
    # 再读取编号变量
    for i in range(1, 50):
        raw = os.environ.get("MINISO_RAW_HEADERS_{}".format(i), "")
        if not raw:
            continue
        parsed = parse_identity_from_raw(raw)
        if parsed["skey"]:
            remark = parsed.get("remark", "")
            if not remark:
                remark = "账号{}".format(i)
            accounts.append((parsed, remark))
    return accounts


# 全局身份(运行时会按账号切换)
IDENTITY = {"skey": "", "openid": "", "unionid": "", "uid": "", "remark": ""}

# ========== 常量 ==========
API_BASE = "https://api-saas.miniso.com/task-manage-platform"
ACTIVITY_ID = "18"
DEFAULT_STORE_ID = "ZGZ4"
WAIT_SECONDS = 20  # 抓包确认 browseTime=20
DEFAULT_PAGE_NAME = "潮玩签到页面"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541f37) XWEB/25799"

DEBUG = "--debug" in sys.argv


def log(msg):
    print(msg)
    if DEBUG:
        sys.stdout.flush()


def md5_upper(s):
    return hashlib.md5(str(s).encode("utf-8")).hexdigest().upper()


def gen_nonce(n=32):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(n))


def make_biz_headers(body_str, page_name, scene_id="1256"):
    """业务签名 headers(用于 api-saas.miniso.com)"""
    t = str(int(time.time() * 1000))
    n = gen_nonce()
    page_encode = urllib.parse.quote(page_name or DEFAULT_PAGE_NAME)
    h = {
        "host": "api-saas.miniso.com",
        "content-type": "application/json",
        "version": "storeexpress1.0",
        "tenant-code": "MINISO",
        "tenant": "MINISO",
        "x-mi-version": "5.2.1",
        "x-client-source": "MINISO_WX_MINI",
        "content-weappcode": "52",
        "content-appcode": "51",
        "content-sceneid": scene_id,
        "content-pagetype": page_encode,
        "content-pagename": page_encode,
        "x-mi-store-id": DEFAULT_STORE_ID,
        "content-skey": IDENTITY["skey"],
        "content-openid": IDENTITY["openid"],
        "content-unionid": IDENTITY["unionid"],
        "content-uid": IDENTITY["uid"],
        "content-latitude": "[object Undefined]",
        "content-longitude": "[object Undefined]",
        "x-mi-city": "",
        "xweb_xhr": "1",
        "user-agent": UA,
        "accept": "*/*",
        "referer": "https://servicewechat.com/wx2a212470bade49bf/1145/page-frame.html",
        "can-flash-send": "true",
        "time": t,
        "nonce": n,
        "signature": md5_upper(str(body_str) + t + n),
    }
    return h


def biz_post(url_path, body, page_name=None, scene_id="1256"):
    """发送带业务签名的 POST 请求"""
    body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    url = API_BASE + url_path
    headers = make_biz_headers(body_str, page_name, scene_id)
    if DEBUG:
        log("[DEBUG] POST " + url)
        log("[DEBUG] Body: " + body_str)
        for k, v in headers.items():
            log("  " + k + ": " + v)
    req = urllib.request.Request(url, data=body_str.encode("utf-8"),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] 响应: " + text)
            return json.loads(text)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] HTTP错误响应: " + text)
            return json.loads(text)
        except Exception:
            if DEBUG:
                log("[DEBUG] HTTP错误: {} {}".format(e.code, e.reason))
            return {"code": e.code, "message": str(e.reason)}
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 请求异常: " + str(e))
        return {"code": -1, "message": str(e)}


def decode_response(raw_bytes):
    """自动处理 gzip 解压"""
    if raw_bytes[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(raw_bytes)
        except Exception:
            pass
    return raw_bytes


def biz_get(url_path, sign_base):
    """GET 请求（支持自定义签名基础字符串）"""
    t = str(int(time.time() * 1000))
    n = gen_nonce()
    url = API_BASE + url_path
    page_encode = urllib.parse.quote(DEFAULT_PAGE_NAME)
    headers = {
        "host": "api-saas.miniso.com",
        "version": "storeexpress1.0",
        "tenant-code": "MINISO",
        "tenant": "MINISO",
        "x-mi-version": "5.2.1",
        "x-client-source": "MINISO_WX_MINI",
        "content-weappcode": "52",
        "content-appcode": "51",
        "content-sceneid": "1256",
        "content-pagetype": page_encode,
        "content-pagename": page_encode,
        "x-mi-store-id": DEFAULT_STORE_ID,
        "content-skey": IDENTITY["skey"],
        "content-openid": IDENTITY["openid"],
        "content-unionid": IDENTITY["unionid"],
        "content-uid": IDENTITY["uid"],
        "content-latitude": "[object Undefined]",
        "content-longitude": "[object Undefined]",
        "x-mi-city": "",
        "user-agent": UA,
        "accept": "*/*",
        "referer": "https://servicewechat.com/wx2a212470bade49bf/1145/page-frame.html",
        "can-flash-send": "true",
        "time": t,
        "nonce": n,
        "signature": md5_upper(str(sign_base) + t + n),
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] GET " + url)
                log("[DEBUG] 响应: " + text)
            return json.loads(text)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] HTTP错误响应: " + text)
            return json.loads(text)
        except Exception:
            if DEBUG:
                log("[DEBUG] HTTP错误: {} {}".format(e.code, e.reason))
            return {"code": e.code, "message": str(e.reason)}
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 请求异常: " + str(e))
        return {"code": -1, "message": str(e)}


def simple_post(url, data_bytes, headers):
    """发送不带业务签名的 POST 请求(用于 cdn-storeexpress 等)"""
    if DEBUG:
        log("[DEBUG] POST " + url)
        log("[DEBUG] Body: " + (data_bytes.decode("utf-8") if data_bytes else "(null)"))
        for k, v in headers.items():
            log("  " + k + ": " + v)
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] 响应: " + text)
            return json.loads(text)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] HTTP错误响应: " + text)
            return json.loads(text)
        except Exception:
            if DEBUG:
                log("[DEBUG] HTTP错误: {} {}".format(e.code, e.reason))
            return {"code": e.code, "message": str(e.reason)}
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 请求异常: " + str(e))
        return {"code": -1, "message": str(e)}


# ========== mini 币余额查询 ==========
def get_mini_balance():
    """查询当前 mini 币余额, 返回整数数量"""
    url = API_BASE + "/api/virtualCoin/memberV2"
    headers = make_biz_headers("", DEFAULT_PAGE_NAME, scene_id="1256")
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            r = json.loads(decoded.decode("utf-8", errors="replace"))
            if DEBUG:
                log("[DEBUG] 余额响应: " + json.dumps(r, ensure_ascii=False)[:300])
            code = r.get("code", -1)
            if code == 200 or str(code) == "200":
                data = r.get("data", {})
                qty = data.get("quantity")
                if qty is not None:
                    return int(qty)
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 余额查询异常: " + str(e))
    return None


# ========== 透视卡兑换相关 ==========
def get_exchange_info():
    """查询可兑换商品列表及剩余次数, 返回透视卡剩余兑换次数"""
    url = API_BASE + "/api/virtualCoin/getVirtualCoinExchangeInfo"
    headers = make_biz_headers("", DEFAULT_PAGE_NAME, scene_id="1256")
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            r = json.loads(decoded.decode("utf-8", errors="replace"))
            if DEBUG:
                log("[DEBUG] 兑换信息响应: " + json.dumps(r, ensure_ascii=False)[:500])
            code = r.get("code", -1)
            if code == 200 or str(code) == "200":
                data = r.get("data", [])
                for item in data:
                    if item.get("id") == 131:  # 透视卡
                        return item.get("exchangeNum", 0)
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 兑换信息查询异常: " + str(e))
    return None


def exchange_perspective_card():
    """兑换1张透视卡, 返回 (success, message)"""
    body = {"configId": 131}
    r = biz_post("/api/virtualCoin/exchange", body, DEFAULT_PAGE_NAME, scene_id="1256")
    code = r.get("code", -1)
    if code == 200 or str(code) == "200":
        data = r.get("data", "")
        return True, "兑换成功 (扣除 {} mini币)".format(data)
    msg = r.get("message", r.get("msg", str(r)))
    # 已兑换过 / 次数用完等也算已知状态
    if any(k in str(msg) for k in ["已兑换", "次数", "限制", "不足", "重复"]):
        return False, "跳过: " + str(msg)
    return False, "兑换失败: " + str(msg)


def exchange_perspective_cards(count=3):
    """兑换多次透视卡, 返回 (success_count, messages)"""
    ok_count = 0
    messages = []
    for i in range(count):
        ok, msg = exchange_perspective_card()
        messages.append(msg)
        if ok:
            ok_count += 1
            if i < count - 1:
                time.sleep(0.5 + random.random() * 0.5)
        else:
            break
    return ok_count, messages


def get_hint_cards():
    """查询抽盒机道具(透视卡/提示卡)持有数及过期信息
    返回: (insight_count, hint_count, expired_list)
    expired_list: [(expire_time_str, change_qty), ...] 按过期时间升序, 最多3条
    """
    # 1. 查询当前持有数
    url = "https://api.multibrands.miniso.com/multi-game-platform/boxDrawer/page/props"
    page = urllib.parse.quote(DEFAULT_PAGE_NAME)
    headers = {
        "host": "api.multibrands.miniso.com",
        "content-type": "application/json",
        "version": "storeexpress1.0",
        "tenant-code": "MINISO",
        "tenant": "MINISO",
        "x-mi-version": "5.2.1",
        "x-client-source": "MINISO_WX_MINI",
        "content-weappcode": "52",
        "content-appcode": "51",
        "content-sceneid": "1256",
        "content-pagetype": page,
        "content-pagename": page,
        "x-mi-store-id": DEFAULT_STORE_ID,
        "content-skey": IDENTITY["skey"],
        "content-openid": IDENTITY["openid"],
        "content-unionid": IDENTITY["unionid"],
        "content-uid": IDENTITY["uid"],
        "user-agent": UA,
        "accept": "*/*",
        "referer": "https://servicewechat.com/wx2a212470bade49bf/1145/page-frame.html",
        "accept-encoding": "gzip, deflate, br",
    }
    insight_count = None
    hint_count = None
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            r = json.loads(decoded.decode("utf-8", errors="replace"))
            if DEBUG:
                log("[DEBUG] 道具持有响应: " + json.dumps(r, ensure_ascii=False)[:300])
            code = r.get("code", -1)
            if code == 200 or str(code) == "200":
                data = r.get("data", {})
                insight_count = data.get("insightCardNum")
                hint_count = data.get("hintCardNum")
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 道具持有查询异常: " + str(e))

    # 2. 查询过期时间 (flow 接口)
    expired_list = []
    flow_url = "https://api.multibrands.miniso.com/multi-game-platform/boxDrawer/page/props/flow"
    for card_type in [0, 1]:  # 0=透视卡, 1=提示卡
        body = {"cardType": card_type, "pageNum": 1, "pageSize": 10}
        body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        try:
            req = urllib.request.Request(flow_url, data=body_str.encode("utf-8"),
                                         headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
                decoded = decode_response(raw)
                r = json.loads(decoded.decode("utf-8", errors="replace"))
                if DEBUG:
                    log("[DEBUG] flow({})响应: ".format(card_type) + json.dumps(r, ensure_ascii=False)[:500])
                code = r.get("code", -1)
                if code == 200 or str(code) == "200":
                    data = r.get("data", {})
                    result_list = data.get("resultList", [])
                    for item in result_list:
                        if not item.get("expired") and item.get("gain"):
                            expire_time = item.get("expireTime", "")
                            if expire_time:
                                expired_list.append((expire_time, item.get("changeQty", 0)))
        except Exception as e:
            if DEBUG:
                log("[DEBUG] flow({})查询异常: ".format(card_type) + str(e))

    # 按过期时间升序排序, 取前3条
    expired_list.sort(key=lambda x: x[0])
    return insight_count, hint_count, expired_list[:3]


def parse_result(name, r):
    """解析响应, 判定成功/失败/跳过"""
    code = r.get("code", -1)
    msg = str(r.get("message", r.get("msg", r.get("data", ""))))
    
    # 成功判定
    if code == 200 or str(code) == "200":
        data = r.get("data", {})
        award = data.get("awardName") if isinstance(data, dict) else None
        if award:
            return True, "[{}] 成功, 获得 {}".format(name, award)
        return True, "[{}] 成功: {}".format(name, msg)
    
    # 跳过判定(已做过 / 不存在已完成的奖励) — 这些不算失败
    skip_msgs = ["重复", "已领取", "已过期", "次数已达",
                 "already", "不可重复", "已做过", "task repeat",
                 "不存在已完成待领取"]
    if any(s in msg for s in skip_msgs):
        return True, "[{}] 跳过(已做): {}".format(name, msg)
    
    # 失败
    return False, "[{}] 失败: {}".format(name, msg)


# ========== 接口调用 ==========
def uv_click(task_id, task_type, page_name):
    """uvClick: 点击浏览上报 (scene=1005)"""
    body = {"activityId": ACTIVITY_ID, "taskId": int(task_id),
            "taskType": int(task_type)}
    return biz_post("/api/activity/task/uvClick", body, page_name, scene_id="1005")


def record_click(task_id, activity_id, page_path, share_code, name):
    """recordClick: 记录浏览页面 (cdn-storeexpress, 需完整业务身份头, body=null)"""
    other_id = "/specialPage/pages/index/index?id={}&shareCode={}&name={}&taskId={}&activityId={}&countDown=1".format(
        page_path, share_code, name, task_id, activity_id)
    url = "https://cdn-storeexpress.miniso.com/new-arrival-calendar/recordClick?otherId=" + urllib.parse.quote(other_id, safe='')
    # 完整业务签名头, 但 host 换成 cdn-storeexpress
    body_str = "null"
    headers = make_biz_headers(body_str, "落地页", scene_id="1005")
    headers["host"] = "cdn-storeexpress.miniso.com"
    headers.pop("can-flash-send", None)
    headers["accept-encoding"] = "gzip, deflate, br"
    return simple_post(url, b"null", headers)


def browse_finish(task_id, page_name):
    """浏览完成: /api/activity/task/browse/finish"""
    body = {"activityId": int(ACTIVITY_ID), "taskId": int(task_id)}
    # 该接口在 api.multibrands.miniso.com 域名下
    url = "https://api.multibrands.miniso.com/multi-configure-platform/api/activity/task/browse/finish"
    body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    headers = make_biz_headers(body_str, page_name, scene_id="1005")
    headers["host"] = "api.multibrands.miniso.com"
    if DEBUG:
        log("[DEBUG] POST " + url)
        log("[DEBUG] Body: " + body_str)
        for k, v in headers.items():
            log("  " + k + ": " + v)
    req = urllib.request.Request(url, data=body_str.encode("utf-8"),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] 响应: " + text)
            return json.loads(text)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            decoded = decode_response(raw)
            text = decoded.decode("utf-8", errors="replace")
            if DEBUG:
                log("[DEBUG] HTTP错误响应: " + text)
            return json.loads(text)
        except Exception:
            if DEBUG:
                log("[DEBUG] HTTP错误: {} {}".format(e.code, e.reason))
            return {"code": e.code, "message": str(e.reason)}
    except Exception as e:
        if DEBUG:
            log("[DEBUG] 请求异常: " + str(e))
        return {"code": -1, "message": str(e)}


def get_task_detail(task_id):
    """获取任务详情(api.multibrands, 无需业务签名), 返回 data 字典
    含: taskType / taskStatus / browsePagePath / browseTime
    """
    url = ("https://api.multibrands.miniso.com/multi-configure-platform/api/activity/task/detail"
           "?activityId={}&taskId={}".format(ACTIVITY_ID, int(task_id)))
    page = urllib.parse.quote(DEFAULT_PAGE_NAME)
    headers = {
        "host": "api.multibrands.miniso.com",
        "content-type": "application/json",
        "version": "storeexpress1.0",
        "tenant-code": "MINISO",
        "tenant": "MINISO",
        "x-mi-version": "5.2.1",
        "x-client-source": "MINISO_WX_MINI",
        "content-weappcode": "52",
        "content-appcode": "51",
        "content-sceneid": "1005",
        "content-pagetype": page,
        "content-pagename": page,
        "x-mi-store-id": DEFAULT_STORE_ID,
        "content-skey": IDENTITY["skey"],
        "content-openid": IDENTITY["openid"],
        "content-unionid": IDENTITY["unionid"],
        "content-uid": IDENTITY["uid"],
        "user-agent": UA,
        "accept": "*/*",
        "referer": "https://servicewechat.com/wx2a212470bade49bf/1145/page-frame.html",
        "accept-encoding": "gzip, deflate, br",
    }
    if DEBUG:
        log("[DEBUG] GET " + url)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            decoded = decode_response(raw)
            r = json.loads(decoded.decode("utf-8", errors="replace"))
            if DEBUG:
                log("[DEBUG] 响应: " + json.dumps(r, ensure_ascii=False)[:500])
            code = r.get("code", -1)
            if code == 200 or str(code) == "200":
                return r.get("data", {})
    except Exception as e:
        if DEBUG:
            log("[DEBUG] task/detail 异常: " + str(e))
    return {}


def parse_browse_page_path(path):
    """从 browsePagePath 解析 (id, shareCode, name)
    例: /specialPage/pages/index/index?id=8884&shareCode=Jdk&name=pro_8884
    """
    if not path or "?" not in path:
        return None
    qs = path.split("?", 1)[1]
    try:
        params = dict(urllib.parse.parse_qsl(qs))
    except Exception:
        return None
    if not params.get("id"):
        return None
    return (params.get("id"), params.get("shareCode"), params.get("name"))


def scan_tasks(start=250, end=310):
    """自动扫描浏览任务(taskType=5), 返回 [(taskId, name, status), ...]
    status: 1=未完成, 2=已完成待领, 3=已领取
    """
    tasks = []
    log("\n[扫描] 正在自动扫描浏览任务 (taskId {}-{})...".format(start, end))
    for tid in range(start, end + 1):
        d = get_task_detail(tid)
        if not d or d.get("taskType") != 5:
            continue
        status = d.get("taskStatus", 0)
        path = d.get("browsePagePath", "")
        bt = d.get("browseTime", 20)
        # 从 path 中的 name 推断任务名
        name = "浏览任务-{}".format(tid)
        parsed = parse_browse_page_path(path)
        if parsed:
            _, _, pro_name = parsed
            if pro_name:
                name = "浏览{}".format(pro_name)
        status_map = {1: "未完成", 2: "已完成待领", 3: "已领取"}
        status_str = status_map.get(status, "未知({})".format(status))
        log("  发现: taskId={} {} (status={}, browseTime={}s)".format(tid, name, status_str, bt))
        tasks.append({"taskId": tid, "name": name, "status": status, "status_str": status_str})
        # 扫描间隔, 避免请求过快
        time.sleep(0.15 + random.random() * 0.1)
    log("[扫描] 共发现 {} 个浏览任务".format(len(tasks)))
    return tasks


def claim_receive(task_id, page_name):
    """领取奖励接口"""
    body = {"activityId": ACTIVITY_ID, "taskId": int(task_id)}
    return biz_post("/api/activity/periodTask/award/receive", body, page_name, scene_id="1256")


# ========== 任务流程 ==========
def browse_flow(name, task_id, task_type, page_name, page_path=None, share_code=None, pro_name=None):
    """浏览任务流程: 0.自动获取页面参数 1.uvClick 2.recordClick 3.等待 4.标记完成 5.领取"""
    log("\n[任务] " + name + " (taskId=" + str(task_id) + ")")

    # 第0步: 自动获取该任务的浏览页面参数与时长 (无签名片段, 从 task/detail 取)
    detail = get_task_detail(task_id)
    browse_time = WAIT_SECONDS
    if detail:
        path = detail.get("browsePagePath")
        parsed = parse_browse_page_path(path)
        if parsed:
            page_path, share_code, pro_name = parsed
            log("  [自动] 页面参数: id={}, shareCode={}, name={}".format(page_path, share_code, pro_name))
        bt = detail.get("browseTime")
        if bt:
            browse_time = int(bt)
            log("  [自动] 浏览时长: {} 秒".format(browse_time))
    elif not (page_path and share_code and pro_name):
        log("  [错误] task/detail 获取失败且无内置参数, 无法继续")
        return False
    if not (page_path and share_code and pro_name):
        # 兜底默认(毛绒节已知参数), 仅当自动获取完全失败时使用
        page_path, share_code, pro_name = "8884", "Jdk", "pro_8884"

    # 第1步: uvClick 点击浏览上报
    log("  第1步: uvClick 点击上报...")
    ok, text = parse_result(name + "(uvClick)", uv_click(task_id, task_type, page_name))
    log("  " + text)
    if not ok:
        return False

    # 第2步: recordClick 记录浏览页面
    log("  第2步: recordClick 记录浏览页面...")
    ok2, text2 = parse_result(name + "(recordClick)", 
                              record_click(task_id, ACTIVITY_ID, page_path, share_code, pro_name))
    log("  " + text2)
    if not ok2:
        log("  [错误] recordClick 失败, 浏览任务未激活, 停止")
        return False

    # 第3步: 等待浏览时长
    log("  第3步: 等待 {} 秒模拟浏览...".format(browse_time))
    time.sleep(browse_time)

    # 第4步: 标记浏览完成
    log("  第4步: browse_finish 标记浏览完成...")
    ok3, text3 = parse_result(name + "(browse_finish)", browse_finish(task_id, page_name))
    log("  " + text3)
    if not ok3:
        log("  [错误] browse_finish 失败, 浏览任务未完成, 停止")
        return False

    # 第5步: 领取奖励
    log("  第5步: 领取奖励...")
    ok4, text4 = parse_result(name + "(领取)", claim_receive(task_id, page_name))
    log("  " + text4)
    if ok4:
        log("  [完成] " + name + " 积分已到账")
        return True

    log("  [提醒] 领取失败, 请用 --debug 查看响应, 并抓包核对领取接口")
    return False


def identity_check():
    """身份自检"""
    log("[自检] 验证身份信息...")
    url_path = "/api/activity/signInTask/taskDetail?activityId=" + ACTIVITY_ID
    r = biz_get(url_path, "signInTaskDetail" + ACTIVITY_ID)
    code = r.get("code", -1)
    if code == 200 or str(code) == "200":
        return True, "身份信息有效"
    msg = str(r.get("message", r.get("msg", str(r))))
    if code in (401, 403) or any(k in msg for k in ["token", "expire", "登录", "鉴权"]):
        return False, "身份信息已过期, 请更新 skey"
    return True, "自检通过(非身份问题)"


# ========== 签到逻辑 ==========
def get_signin_detail():
    """查询今日签到状态"""
    url_path = "/api/activity/signInTask/taskDetail?activityId={}".format(ACTIVITY_ID)
    return biz_get(url_path, "signInTaskDetail" + ACTIVITY_ID)


def complete_signin(task_id):
    """执行签到领奖"""
    body = {"activityId": str(ACTIVITY_ID), "taskId": task_id}
    return biz_post("/api/activity/signInTask/award/receive", body, DEFAULT_PAGE_NAME, scene_id="1256")


def do_signin():
    """完整签到流程"""
    log("[签到] 查询今日签到状态...")
    detail = get_signin_detail()
    if DEBUG:
        log("[签到] 查询返回: " + json.dumps(detail, ensure_ascii=False))

    code = detail.get("code", -1)
    if code != 200 and str(code) != "200":
        msg = detail.get("message", detail.get("msg", str(detail)))
        log("[签到] 查询失败: {}".format(msg))
        return False, "查询失败"

    data = detail.get("data", {})
    task_id = data.get("taskId")
    finish_flag = data.get("todaySignInFinishFlag")

    if finish_flag == 1 or finish_flag is True:
        days = data.get("signInFinishDays", "?")
        log("[签到] 今日已签到, 连续 {} 天".format(days))
        return True, "已签到(连续{}天)".format(days)

    if task_id is None or task_id == "":
        log("[签到] 未获取到 taskId: " + json.dumps(data, ensure_ascii=False))
        return False, "无taskId"

    log("[签到] 执行签到领奖 (taskId={})...".format(task_id))
    result = complete_signin(task_id)
    if DEBUG:
        log("[签到] 领奖返回: " + json.dumps(result, ensure_ascii=False))

    if result.get("code") == 200 or str(result.get("code")) == "200":
        log("[签到] 签到成功!")
        return True, "签到成功"

    msg = result.get("message", result.get("msg", str(result)))
    if any(k in str(msg) for k in ["已签", "签到过", "重复", "已完成", "已领取"]):
        log("[签到] 今日已签到 ({})".format(msg))
        return True, "已签到"

    log("[签到] 签到失败: {}".format(msg))
    return False, "失败: {}".format(msg)


# ========== 任务列表 ==========
# 页面参数(id/shareCode/name)与浏览时长会自动从 task/detail 获取, 无需填写
# 只需提供 name/taskId/taskType (taskId 从抓包获得)
TASKS = [
    {"name": "浏览任务-287", "taskId": 287, "taskType": 5},
    {"name": "浏览任务-285", "taskId": 285, "taskType": 5},
    {"name": "浏览任务-281", "taskId": 281, "taskType": 5},
    {"name": "浏览任务-276", "taskId": 276, "taskType": 5},
    {"name": "浏览任务-262", "taskId": 262, "taskType": 5},
]


if __name__ == "__main__":
    print("=== 名创优品浏览任务 ===")
    print("运行时间: " + time.strftime("%Y-%m-%d %H:%M:%S"))

    # ========== 代理初始化 ==========
    # 1. 检查环境变量中的直接代理设置
    http_proxy, https_proxy = get_proxy_from_env()
    
    # 2. 如果环境变量没有代理，尝试从API获取
    if not http_proxy and not https_proxy:
        proxy_api_url = os.environ.get("PROXY_API_URL")
        proxy_api_key = os.environ.get("PROXY_API_KEY")
        if proxy_api_url:
            print("[代理] 正在从API获取代理IP...")
            proxy = get_proxy_from_api(proxy_api_url, proxy_api_key)
            if proxy:
                http_proxy = proxy
                https_proxy = proxy
                print("[代理] 已获取代理: " + proxy)
            else:
                print("[代理] API获取失败，将使用直接连接")
        else:
            print("[代理] 未配置代理API，将使用直接连接")
    else:
        print("[代理] 使用环境变量代理: " + str(http_proxy))
    
    # 3. 配置代理
    if http_proxy or https_proxy:
        setup_proxy(http_proxy, https_proxy)
        print("[代理] 代理已启用")
    
    accounts = load_all_accounts()
    if not accounts:
        print("\n[错误] 未找到任何账号配置, 请设置环境变量")
        sys.exit(1)

    print("共 {} 个账号".format(len(accounts)))

    # 存储每个账号的执行结果: (remark, before, after, ok_count, signin_status, status_msg)
    results = []

    for idx, (account_identity, remark) in enumerate(accounts):
        # 设置全局身份(供所有接口函数使用)
        IDENTITY = account_identity

        print("\n" + "=" * 40)
        print("[账号] {} (第{}/{}个)".format(remark, idx + 1, len(accounts)))

        if not all(IDENTITY.values()):
            print("[错误] 身份信息不完整, 跳过此账号")
            results.append((remark, None, None, 0, "未执行", "身份不完整"))
            continue

        ok, msg = identity_check()
        if not ok:
            print("[错误] " + msg + ", 跳过此账号")
            results.append((remark, None, None, 0, "未执行", msg))
            continue
        log("[自检] " + msg)

        # 签到
        signin_ok, signin_msg = do_signin()
        signin_status = "签到成功" if signin_ok else "签到失败: " + signin_msg

        # 查询任务前余额
        before = get_mini_balance()
        if before is not None:
            print("[余额] 任务前 mini 币: {}".format(before))
        else:
            print("[余额] 任务前查询失败")

        # 扫描浏览任务
        scan_start = int(os.environ.get("MINISO_SCAN_START", 250))
        scan_end = int(os.environ.get("MINISO_SCAN_END", 310))
        scanned = scan_tasks(scan_start, scan_end)

        # 过滤待执行任务
        pending_tasks = [t for t in scanned if t["status"] in (1, 2)]
        skipped_tasks = [t for t in scanned if t["status"] == 3]

        if skipped_tasks:
            print("\n[跳过] {} 个已领取任务:".format(len(skipped_tasks)))
            for t in skipped_tasks:
                print("  - {} (taskId={})".format(t["name"], t["taskId"]))

        if not pending_tasks:
            print("\n[信息] 无待执行浏览任务")
            after = get_mini_balance()
            results.append((remark, before, after, 0, signin_status, "无任务"))
            continue

        total = len(pending_tasks)
        print("\n[执行] 共 {} 个待执行浏览任务, 预计耗时约 {} 秒".format(total, total * (WAIT_SECONDS + 3)))

        ok_count = 0
        for i, t in enumerate(pending_tasks):
            ok = browse_flow(t["name"], t["taskId"], 5, DEFAULT_PAGE_NAME)
            if ok:
                ok_count += 1
            if i < total - 1:
                time.sleep(1.5 + random.random() * 1.5)

        # 查询任务后余额
        after = get_mini_balance()
        if after is not None:
            print("[余额] 任务后 mini 币: {}".format(after))
        else:
            print("[余额] 任务后查询失败")

        # ========== 透视卡兑换与查询 ==========
        # 查询当前透视卡持有数与过期时间
        insight_count, _, expired_list = get_hint_cards()
        if insight_count is not None:
            print("\n[透视卡] 当前持有: {} 张".format(insight_count))
            if expired_list:
                print("[透视卡] 最近3张过期时间:")
                for et, qty in expired_list:
                    print("  - {} (数量: {})".format(et, qty))
            else:
                print("[透视卡] 无即将过期的卡")
        else:
            print("\n[透视卡] 持有数查询失败")

        # 查询今日剩余可兑换次数
        exchange_remain = get_exchange_info()
        print("[透视卡] 今日剩余可兑换次数: {}".format(
            exchange_remain if exchange_remain is not None else "查询失败"))

        # 判断余额是否充足 (3次=1200币)
        can_exchange = False
        if after is not None and after >= 1200:
            if exchange_remain is not None and exchange_remain >= 3:
                can_exchange = True

        exchange_results = []
        if can_exchange:
            print("[透视卡] 开始兑换3次透视卡...")
            exchange_ok_count, exchange_msgs = exchange_perspective_cards(3)
            for msg in exchange_msgs:
                print("  " + msg)
            exchange_results = exchange_msgs
        else:
            reason = ""
            if after is not None and after < 1200:
                reason = "余额不足(需1200币)"
            elif exchange_remain is not None and exchange_remain < 3:
                reason = "今日次数已用完"
            else:
                reason = "余额/次数查询失败"
            print("[透视卡] 跳过兑换 ({}), 当前余额: {}, 剩余次数: {}".format(
                reason,
                after if after is not None else "N/A",
                exchange_remain if exchange_remain is not None else "N/A"))

        # 兑换后再次查询持有数与过期时间
        insight_count2, _, expired_list2 = get_hint_cards()
        if insight_count2 is not None:
            print("[透视卡] 兑换后持有: {} 张".format(insight_count2))
            if expired_list2:
                print("[透视卡] 兑换后最近3张过期时间:")
                for et, qty in expired_list2:
                    print("  - {} (数量: {})".format(et, qty))
        else:
            print("[透视卡] 兑换后持有数查询失败")

        results.append((remark, before, after, ok_count, signin_status,
                        "成功", insight_count2, expired_list2, exchange_results))

    # ========== 汇总报告 ==========
    print("\n" + "=" * 70)
    print("汇总报告")
    print("=" * 70)
    print("{:<12} {:>10} {:>8} {:>8} {:>6} {:>8} {:>10} {:>20}".format(
        "账号备注", "签到", "任务前", "任务后", "完成数", "变化", "透视卡", "过期时间"))
    print("-" * 85)
    total_delta = 0
    for remark, before, after, ok_count, signin_status, status, insight_count, expired_list, _ in results:
        delta_str = "N/A"
        if before is not None and after is not None:
            delta = after - before
            total_delta += delta
            delta_str = "{:+d}".format(delta)

        insight_str = str(insight_count) if insight_count is not None else "N/A"
        expired_str = ""
        if expired_list:
            expired_str = ", ".join([et.split()[0] for et, _ in expired_list[:3]])
        else:
            expired_str = "无"

        print("{:<12} {:>10} {:>8} {:>8} {:>6} {:>8} {:>10} {:>20}".format(
            remark,
            signin_status,
            str(before) if before is not None else "N/A",
            str(after) if after is not None else "N/A",
            ok_count,
            delta_str,
            insight_str,
            expired_str))
    print("-" * 85)
    print("总计 mini 币变化: +{}".format(total_delta))
    print("=" * 85)
