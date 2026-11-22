"""
Baseera Sec - Enterprise API Specification Importer & Schema Parser
يقوم باستيراد وتحليل مواصفات الـ APIs المختلفة وتوليد مساحة الهجوم ونقاط الحقن آلياً:
1. OpenAPI / Swagger v2 & v3 (JSON & YAML)
2. Postman Collections (v2.0 & v2.1)
3. GraphQL Schemas & Introspection Endpoints
يدعم توليد حمولات JSON و XML و Form-Data و Multipart
"""
import json
import re
import yaml
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin
from core.recon.surface.param_extractor import InjectionPoint

class APISchemaParser:

    @classmethod
    def parse_schema_content(cls, content: str, base_url: str) -> List[InjectionPoint]:
        """
        التحليل الذكي التلقائي لمحتوى الملف (سواء كان Swagger أو Postman أو GraphQL)
        """
        points = []
        content_clean = content.strip()

        # 1. محاولة قراءة JSON
        try:
            data = json.loads(content_clean)
            if isinstance(data, dict):
                # فحص هل هو Postman Collection
                if "info" in data and ("_postman_id" in data["info"] or "schema" in data["info"]):
                    return cls.parse_postman_collection(data, base_url)
                # فحص هل هو OpenAPI / Swagger
                if "openapi" in data or "swagger" in data or "paths" in data:
                    return cls.parse_openapi_spec(data, base_url)
        except Exception:
            pass

        # 2. محاولة قراءة YAML (Swagger / OpenAPI)
        try:
            yaml_data = yaml.safe_load(content_clean)
            if isinstance(yaml_data, dict) and ("openapi" in yaml_data or "swagger" in yaml_data or "paths" in yaml_data):
                return cls.parse_openapi_spec(yaml_data, base_url)
        except Exception:
            pass

        # 3. محاولة قراءة كود GraphQL Schema
        if "type Query" in content_clean or "type Mutation" in content_clean or "schema {" in content_clean:
            return cls.parse_graphql_schema(content_clean, base_url)

        return points

    @classmethod
    def parse_openapi_spec(cls, spec: Dict[str, Any], base_url: str) -> List[InjectionPoint]:
        """تحليل مواصفات OpenAPI / Swagger"""
        points = []
        paths = spec.get("paths", {})
        servers = spec.get("servers", [])
        server_prefix = servers[0].get("url", "") if servers else spec.get("basePath", "")

        for path_str, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            full_route = urljoin(base_url, f"{server_prefix.rstrip('/')}/{path_str.lstrip('/')}")

            for method_str, details in methods.items():
                if method_str.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue
                m_upper = method_str.upper()

                if not isinstance(details, dict):
                    continue

                # 1. فحص parameters (Query, Path, Header)
                for param in details.get("parameters", []):
                    if isinstance(param, dict) and "name" in param:
                        p_name = param["name"]
                        p_in = param.get("in", "query")
                        p_type = param.get("schema", {}).get("type", "string") if "schema" in param else param.get("type", "string")
                        dummy_val = "1" if p_type in ["integer", "number"] else "test"
                        points.append(InjectionPoint(
                            param_name=p_name,
                            original_value=dummy_val,
                            method=m_upper,
                            target_url=full_route,
                            is_form_input=(m_upper != "GET")
                        ))

                # 2. فحص requestBody (JSON / XML / Form-Data)
                req_body = details.get("requestBody", {})
                content_types = req_body.get("content", {})
                for c_type, c_details in content_types.items():
                    schema = c_details.get("schema", {})
                    props = schema.get("properties", {})
                    for prop_name, prop_details in props.items():
                        p_type = prop_details.get("type", "string")
                        dummy_val = "1" if p_type in ["integer", "number"] else "test"
                        points.append(InjectionPoint(
                            param_name=prop_name,
                            original_value=dummy_val,
                            method=m_upper,
                            target_url=full_route,
                            is_form_input=True
                        ))

        return points

    @classmethod
    def parse_postman_collection(cls, data: Dict[str, Any], base_url: str) -> List[InjectionPoint]:
        """تحليل مجموعات Postman المصدّرة"""
        points = []

        def extract_items(items_list):
            for item in items_list:
                if "item" in item and isinstance(item["item"], list):
                    extract_items(item["item"])
                elif "request" in item:
                    req = item["request"]
                    method = req.get("method", "GET").upper()
                    url_obj = req.get("url", {})
                    raw_url = url_obj.get("raw", "") if isinstance(url_obj, dict) else str(url_obj)
                    target_endpoint = urljoin(base_url, raw_url)

                    # استخراج Query params
                    if isinstance(url_obj, dict) and "query" in url_obj:
                        for q in url_obj.get("query", []):
                            if isinstance(q, dict) and "key" in q:
                                points.append(InjectionPoint(
                                    param_name=q["key"],
                                    original_value=q.get("value", "1"),
                                    method=method,
                                    target_url=target_endpoint,
                                    is_form_input=False
                                ))

                    # استخراج Body params (JSON / URLencoded / FormData)
                    body_obj = req.get("body", {})
                    b_mode = body_obj.get("mode", "")
                    if b_mode == "urlencoded":
                        for form_p in body_obj.get("urlencoded", []):
                            if "key" in form_p:
                                points.append(InjectionPoint(
                                    param_name=form_p["key"],
                                    original_value=form_p.get("value", "1"),
                                    method=method,
                                    target_url=target_endpoint,
                                    is_form_input=True
                                ))
                    elif b_mode == "formdata":
                        for form_p in body_obj.get("formdata", []):
                            if "key" in form_p and form_p.get("type") != "file":
                                points.append(InjectionPoint(
                                    param_name=form_p["key"],
                                    original_value=form_p.get("value", "1"),
                                    method=method,
                                    target_url=target_endpoint,
                                    is_form_input=True
                                ))
                    elif b_mode == "raw":
                        raw_text = body_obj.get("raw", "")
                        try:
                            json_body = json.loads(raw_text)
                            if isinstance(json_body, dict):
                                for k, v in json_body.items():
                                    points.append(InjectionPoint(
                                        param_name=k,
                                        original_value=str(v),
                                        method=method,
                                        target_url=target_endpoint,
                                        is_form_input=True
                                    ))
                        except Exception:
                            pass

        extract_items(data.get("item", []))
        return points

    @classmethod
    def parse_graphql_schema(cls, schema_text: str, base_url: str) -> List[InjectionPoint]:
        """تحليل دوال ومعاملات GraphQL"""
        points = []
        graphql_endpoint = urljoin(base_url, "/graphql")
        # استخراج العمليات والمعاملات بأنماط Regex: field(arg: Type)
        field_matches = re.findall(r'([a-zA-Z0-9_]+)\s*\(([^)]+)\)', schema_text)
        for field_name, args_str in field_matches:
            for arg_pair in args_str.split(","):
                if ":" in arg_pair:
                    arg_name = arg_pair.split(":")[0].strip()
                    points.append(InjectionPoint(
                        param_name=f"{field_name}.{arg_name}",
                        original_value="1",
                        method="POST",
                        target_url=graphql_endpoint,
                        is_form_input=True
                    ))
        return points
