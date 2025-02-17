from pkg.plugin.models import *
from pkg.plugin.host import EventContext, PluginHost

import logging
import re
import os
import shutil
import yaml
import requests
import json




# Register plugin
@register(name="CVESearch", description="基于GPT的函数调用能力，为QChatGPT提供CVE漏洞信息搜索功能", version="0.1.3", author="RockChinQ")
class WebwlkrPlugin(Plugin):

    # Triggered when plugin is loaded
    def __init__(self, plugin_host: PluginHost):
        pass

    @func("search_the_cve")
    def _(cve_number: str, brief_len: int = 1080):
        """Call this function when asking you to search some vulnerability or some CVE 
        - Summary the plain content result by yourself

        Args:
            cve_number(str): the number of cve like "CVE-2021-3156"
            brief_len(int): max length of the plain text content, recommend 1024-4096, prefer 4096. If not provided, default value from config will be used.

        Returns:
            str: plain text content of the web page or error message(starts with 'error:')
        """
        try:
            url = f"https://cve.circl.lu/api/cve/{cve_number}"
            response = requests.get(url)
            if response.status_code != 200:
                return f"无法获取CVE信息: {response.status_code}"
            cve_data = response.json()
            cve_id = cve_data.get("cveMetadata", {}).get("cveId", "无ID")
            description = cve_data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "无描述")
            cvss_score = cve_data.get("metrics", [{}])[0].get("cvssV3_1", {}).get("baseScore", "无CVSS评分")
            references = "\n".join([ref.get('url', '无链接') for ref in cve_data.get("containers", {}).get("cna", {}).get("references", [])])

            brief_text = f"""
            CVE编号: {cve_id}
            描述: {description}
            CVSS评分: {cvss_score}
            参考链接: 
            {references}
            """
            return brief_text[:brief_len] if len(brief_text) > brief_len else brief_text.strip()
        except Exception as e:
            return f"查询CVE信息失败: {e}"

    # Triggered when plugin is uninstalled
    def __del__(self):
        pass

