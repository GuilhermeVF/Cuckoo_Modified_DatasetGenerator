# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.http import JsonResponse

from cuckoo.common.exceptions import CuckooApiError

from cuckoo.web.controllers.analysis.analysis import AnalysisController
from cuckoo.web.controllers.analysis.export.export import ExportController
from cuckoo.web.utils import api_post, json_error_response

import pymongo
from cuckoo.common.mongo import mongo
import pandas as pd

class ExportApi:
    @api_post
    def export_estimate_size(request, body):
        task_id = body.get('task_id')
        taken_dirs = body.get("dirs", [])
        taken_files = body.get("files", [])

        if not taken_dirs and not taken_files:
            return JsonResponse({"size": 0, "size_human": "-"}, safe=False)

        if not task_id:
            return json_error_response("invalid task_id")

        size = ExportController.estimate_size(task_id=task_id,
                                              taken_dirs=taken_dirs,
                                              taken_files=taken_files)

        return JsonResponse(size, safe=False)

    @api_post
    def get_files(request, body):
        task_id = body.get('task_id', None)

        if not task_id:
            return json_error_response("invalid task_id")

        report = AnalysisController.get_report(task_id)
        if not report["analysis"].get("info", {}).get("analysis_path"):
            raise CuckooApiError("old-style analysis")

        analysis_path = report["analysis"]["info"]["analysis_path"]

        try:
            dirs, files = ExportController.get_files(analysis_path)
        except Exception as e:
            return json_error_response(message=str(e))

        return JsonResponse({"dirs": dirs, "files": files}, safe=False)

    @api_post
    def data_set(request, body):
        # Create Structures
        selected_nodes = body.get('selected_nodes', [])

        url_adds = body.get('url_adds', [])
        api_adds = body.get('api_adds', [])
        dlls_adds = body.get('dlls_adds', [])
        signature_adds = body.get('signature_adds', [])
        strings_adds = body.get('strings_adds', [])

        rows = mongo.db.analysis.find(
            {},
            ["info", "target", "behavior", "strings", "signatures", "virustotal", "procmemory"],
            sort=[("_id", pymongo.DESCENDING)]
        )

        # Populate Data_Frame
        data_frame = pd.DataFrame()
        for row in rows:
            task = {}
            for selected_node in selected_nodes:
                hierarchy = selected_node.split('.')
                collection_name = hierarchy[0]
                collection = row.get(collection_name, {})
                
                hierarchy_iterator = collection
                for item in hierarchy[1:]:
                    hierarchy_iterator = hierarchy_iterator.get(item, {})

                if hierarchy_iterator == {}:
                    task[selected_node] = ''
                else:
                    task[selected_node] = hierarchy_iterator

            proc_memory_collection = row.get("procmemory", {})
            for url_add in url_adds:
                url_exists = False
                for process in proc_memory_collection:
                    for url in process.get("urls", ''):
                        if (url_add.lower().strip() == url.lower().strip()) or ("http://" + url_add.lower().strip() == url.lower().strip()) or ("https://" + url_add.lower().strip() == url.lower().strip()) or ("www." + url_add.lower().strip() == url.lower().strip()) or ("http://www." + url_add.lower().strip() == url.lower().strip()) or ("https://www." + url_add.lower().strip() == url.lower().strip()):
                            url_exists = True
                            break
                task[url_add] = url_exists

            behavior_collection = row.get("behavior", {})
            for api_add in api_adds:
                api_exists = False
                processes_apis = behavior_collection.get("apistats", {})
                for process_name in processes_apis:
                    process_apis_names = set(k.lower().strip() for k in processes_apis[process_name])
                    if api_add.lower().strip() in process_apis_names:
                        api_exists = True
                        break
                task[api_add] = api_exists

            for dll_add in dlls_adds:
                dll_exists = False
                dlls_loaded = behavior_collection.get("summary", {}).get("dll_loaded", {})
                for dll in dlls_loaded:
                    dll_formatted = str(dll.split('\\')[-1]).lower().strip()
                    dll_add_formatted = str(dll_add).lower().strip()
                    if dll_add_formatted.endswith(".dll"):
                        dll_add_formatted = dll_add_formatted[:-4]

                    if (dll_add_formatted == dll_formatted) or (dll_add_formatted + ".dll" == dll_formatted):
                        dll_exists = True
                        break
                task[dll_add] = dll_exists

            signatures_collection = row.get("signatures", {})
            for signature_add in signature_adds:
                signature_exists = False
                for signature in signatures_collection:
                    if signature_add.lower().strip() == signature.get("name", '').lower().strip():
                        signature_exists = True
                        break
                task[signature_add] = signature_exists

            strings_collection = row.get("strings", {})
            for string_add in strings_adds:
                string_exists = False
                for string in strings_collection:
                    if string_add.lower().strip() == string.lower().strip():
                        string_exists = True
                        break
                task[string_add] = string_exists

            data_frame = data_frame.append(task, ignore_index=True)

        #data_frame_json = data_frame.to_json(orient="records")
        return JsonResponse({"csv_string": data_frame.to_csv()}, safe=False)

