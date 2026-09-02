#!/usr/bin/env python3
"""
main.py - 告警采集引擎（支持文件轮转检测）
version 0.2.0
"""
import os
import sys
import time
import signal
import datetime
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (
    DB_PATH,
    FINANCIAL_FACTORS_FILE,
    COLLECTOR,
    SYSLOG_FILE,
    OFFSET_FILE,
    get_config_summary,
)

from adapters.modsec_adapter import ModSecAdapter
from storage.db_writer import DBWriter
from engine.scorer import Scorer
from engine.id_generator import init_id_generator, get_id_generator

running = True
total_count = 0

def signal_handler(sig, frame):
    global running
    print("\n[Main] 收到退出信号，正在关闭...")
    running = False


def main():
    global running, total_count

    print(f"[Main] 启动采集引擎（支持文件轮转）")
    print(f"[Main] 配置摘要: {get_config_summary()}")
    print(f"[Main] 监控日志文件: {SYSLOG_FILE}")

    # 1. 加载评分配置
    try:
        with open(FINANCIAL_FACTORS_FILE, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[Main] 错误: 配置文件 {FINANCIAL_FACTORS_FILE} 不存在")
        sys.exit(1)
    except Exception as e:
        print(f"[Main] 错误: 加载配置文件失败 - {e}")
        sys.exit(1)

    # 2. 初始化各模块
    id_config = config.get("alert_id", {})
    init_id_generator(id_config, str(DB_PATH))
    id_gen = get_id_generator()
    scorer = Scorer(str(FINANCIAL_FACTORS_FILE))
    db_writer = DBWriter(str(DB_PATH), batch_size=COLLECTOR["batch_size"], flush_interval=COLLECTOR["flush_interval"])
    adapter = ModSecAdapter()

    # 3. 等待日志文件出现
    wait_count = 0
    timeout = COLLECTOR["file_wait_timeout"]
    while not os.path.exists(SYSLOG_FILE) and wait_count < timeout:
        print(f"[Main] 等待日志文件 {SYSLOG_FILE} 出现... ({wait_count}/{timeout})")
        time.sleep(1)
        wait_count += 1

    if not os.path.exists(SYSLOG_FILE):
        print(f"[Main] 错误: 日志文件 {SYSLOG_FILE} 不存在，程序退出")
        sys.exit(1)

    print(f"[Main] 日志文件已就绪: {SYSLOG_FILE}")
    print("[Main] 按 Ctrl+C 停止程序")

    # 4. 告警处理回调
    def handle_parsed_data(schema):
        global total_count
        total_count += 1

        # 所有告警默认不沉底
        schema.is_blocked = 0
        marker = "A"

        try:
            schema.alert_id = id_gen.generate(schema, marker=marker)
        except Exception as e:
            print(f"[ERROR] 编号生成失败: {e}")
            schema.alert_id = f"ERR{int(time.time())}"

        try:
            schema.priority_score = scorer.compute(schema)
        except Exception as e:
            print(f"[WARN] 评分计算失败: {e}")
            schema.priority_score = 0.0

        db_writer.add(schema.to_dict())

    # 5. 主循环（带文件轮转检测）
    current_file_path = SYSLOG_FILE
    f = None
    offset = 0

    try:
        while running:
            # ---- 检查文件是否存在 ----
            if not os.path.exists(current_file_path):
                print(f"[Main] 日志文件 {current_file_path} 不存在，等待...")
                time.sleep(5)
                continue

            # ---- 检查是否需要重新打开文件 ----
            if f is None:
                # 首次打开
                offset = 0
                if os.path.exists(OFFSET_FILE):
                    with open(OFFSET_FILE, 'r') as pf:
                        try:
                            offset = int(pf.read().strip())
                        except:
                            offset = 0
                f = open(current_file_path, 'r')
                # 如果偏移量大于文件大小，重置
                try:
                    if offset > os.path.getsize(current_file_path):
                        offset = 0
                except:
                    offset = 0
                f.seek(offset)
                print(f"[Main] 打开日志文件: {current_file_path}, 从偏移量 {offset} 开始")
            else:
                # 检查文件是否被轮转（通过 inode 比较）
                try:
                    current_inode = os.stat(current_file_path).st_ino
                    open_inode = os.stat(f.fileno()).st_ino
                    if current_inode != open_inode:
                        print(f"[Main] 检测到文件轮转，重新打开日志文件")
                        f.close()
                        f = open(current_file_path, 'r')
                        offset = 0
                        f.seek(0)
                        with open(OFFSET_FILE, 'w') as pf:
                            pf.write("0")
                except Exception as e:
                    print(f"[Main] 检查文件状态异常: {e}")
                    if f:
                        f.close()
                    f = open(current_file_path, 'r')
                    offset = 0
                    f.seek(0)

            # ---- 读取一行 ----
            line = f.readline()
            if not line:
                # 保存当前偏移量
                with open(OFFSET_FILE, 'w') as pf:
                    pf.write(str(f.tell()))
                time.sleep(COLLECTOR["read_sleep_interval"])
                continue

            # ---- 处理日志 ----
            if adapter.match(line):
                try:
                    schema = adapter.parse(line)
                    if schema:
                        handle_parsed_data(schema)
                except Exception as e:
                    print(f"[Main] 解析异常: {e}")

    except KeyboardInterrupt:
        print("[Main] 用户中断")
    finally:
        if f:
            f.close()
        db_writer.flush_on_exit()
        print(f"[Main] 程序已退出, 共处理 {total_count} 条告警")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()
