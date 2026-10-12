# adapters/example_adapter.py
"""
这是一个示例适配器模板。
实现新的设备适配器时，复制此文件并修改即可。
"""
from adapters.base_adapter import BaseAdapter
from storage.models import CommonSchema

class ExampleAdapter(BaseAdapter):
    TAG = "your_device_tag"

    def match(self, raw_line: str) -> bool:
        # 判断这条日志是否属于你的设备
        return self.TAG in raw_line and "{" in raw_line

    def parse(self, raw_line: str) -> CommonSchema:
        schema = CommonSchema()
        schema.vendor = "your_device_name"
        # 解析逻辑...
        return schema