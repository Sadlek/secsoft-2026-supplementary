import json
import re
from pprint import pprint
from time import time

from service_copy import get_vulnllama_service

API_URL = "http://localhost:8000"

QUESTIONS = [
    "Which IP addresses communicated with IP address 10.4.1.12?",
    "Which IP addresses communicated with IP address 10.3.4.44?",
    "Which IP addresses communicated with IP address 4.122.55.2?",
    "Which IP addresses participate in mission called Custom Application - BT3?",
    "Which IP addresses participate in mission called Public-Facing Services - BT4?",
    "Which IP addresses participate in mission called Admin Services - BT2?",
    "Which CVE vulnerabilities are present on a host with IP address 10.4.1.12?",
    "Which CVE vulnerabilities are present on a host with IP address 10.3.1.14?",
    "Which CVE vulnerabilities are present on a host with IP address 4.122.55.2?",
    "Which hosts are jeopardized by lateral movement from IP address 10.6.1.12? Provide IP addresses of such hosts.",
    "Which hosts are jeopardized by lateral movement from IP address 10.1.4.42? Provide IP addresses of such hosts.",
    "Which hosts are jeopardized by lateral movement from IP address 10.1.2.23? Provide IP addresses of such hosts.",
    # Scores for individual vulnerabilities:
    # Winners: CVE-2022-21893, CVE-2020-1379, CVE-2020-0781
    # Middle: CVE-2020-14415, CVE-2020-1141, CVE-2021-1637
    # Worst: CVE-2015-5600, CVE-2016-10009, CVE-2007-3205
    "Which of CVE vulnerabilities: CVE-2020-14415, CVE-2015-5600, CVE-2022-21893 has the highest priority if you consider CVSS of version 2 and jeopardized Host entities from the database?",
    "Which of CVE vulnerabilities: CVE-2020-1379, CVE-2020-1141, CVE-2016-10009 has the highest priority if you consider CVSS of version 2 and jeopardized Host entities from the database?",
    "Which of CVE vulnerabilities: CVE-2007-3205, CVE-2021-1637, CVE-2020-0781 has the highest priority if you consider CVSS of version 2 and jeopardized Host entities from the database?",
    # No mission: CVE-2015-6564, CVE-2015-5600, CVE-2019-19271
    # Winners: CVE-2020-0607, CVE-2022-21893, CVE-2023-21524
    # Middle: CVE-2023-34367, CVE-2021-1637, CVE-2022-29120
    "Which of CVE vulnerabilities: CVE-2015-6564, CVE-2023-34367, CVE-2020-0607 has the highest priority if you consider jeopardized Mission entities from the database?",
    "Which of CVE vulnerabilities: CVE-2015-5600, CVE-2022-21893, CVE-2021-1637 has the highest priority if you consider jeopardized Mission entities from the database?",
    "Which of CVE vulnerabilities: CVE-2022-29120, CVE-2023-21524, CVE-2019-19271 has the highest priority if you consider jeopardized Mission entities from the database?"
]

ANSWERS = {
    "Which IP addresses communicated with IP address 10.4.1.12?": ['4.122.55.5', '10.7.100.5', '4.122.55.3', '10.7.100.3', '4.122.55.7', '10.7.100.7', '4.122.55.1', '4.122.55.114', '4.122.55.226'],
    "Which IP addresses communicated with IP address 10.3.4.44?": ['4.122.55.2', '10.7.100.2', '4.122.55.3', '10.7.100.3', '4.122.55.23'],
    "Which IP addresses communicated with IP address 4.122.55.2?": ['10.1.4.43', '10.7.101.43', '10.3.2.29', '10.7.103.29', '10.4.4.43', '10.7.104.43', '10.4.4.42', '10.7.104.42', '10.2.2.29', '10.7.102.29', '10.4.4.45', '10.7.104.45', '10.4.4.44', '10.7.104.44', '4.122.55.254', '10.4.2.29', '10.7.104.29', '10.1.2.29', '10.7.101.29', '10.5.2.29', '10.7.105.29', '10.6.2.29', '10.7.106.29', '10.1.4.42', '10.7.101.42', '10.6.4.42', '10.7.106.42', '10.6.4.43', '10.7.106.43', '10.6.3.32', '10.7.106.32', '10.6.3.33', '10.7.106.33', '10.6.4.45', '10.7.106.45', '10.6.4.44', '10.7.106.44', '10.2.4.42', '10.7.102.42', '10.2.4.43', '10.7.102.43', '10.5.4.43', '10.7.105.43', '10.5.4.42', '10.7.105.42', '10.5.3.32', '10.7.105.32', '10.5.4.45', '10.7.105.45', '10.5.4.44', '10.7.105.44', '10.2.4.45', '10.7.102.45', '10.2.4.44', '10.7.102.44', '10.5.3.33', '10.7.105.33', '10.1.3.33', '10.7.101.33', '10.1.3.32', '10.7.101.32', '10.1.4.44', '10.7.101.44', '10.1.4.45', '10.7.101.45', '10.2.3.33', '10.7.102.33', '10.2.3.32', '10.7.102.32', '10.3.4.43', '10.7.103.43', '10.3.4.42', '10.7.103.42', '10.3.4.45', '10.7.103.45', '10.3.4.44', '10.7.103.44', '10.3.3.32', '10.7.103.32', '10.3.3.33', '10.7.103.33', '10.4.3.32', '10.7.104.32', '10.4.3.33', '10.7.104.33', '10.7.100.2'],
    "Which IP addresses participate in mission called Custom Application - BT3?": ['10.3.2.28', '10.7.103.28', '10.3.2.29', '10.7.103.29', '10.3.2.26', '10.7.103.26', '10.3.3.33', '10.7.103.33', '10.3.3.32', '10.7.103.32', '10.3.2.25', '10.7.103.25', '10.7.103.24', '10.3.2.24', '10.7.103.23', '10.3.2.23', '10.3.2.27', '10.7.103.27', '10.7.103.22', '10.3.2.22'],
    "Which IP addresses participate in mission called Public-Facing Services - BT4?": ['9.66.44.13', '10.4.1.13', '10.7.104.13', '9.66.44.14', '10.4.1.14', '10.7.104.14', '9.66.44.12', '10.4.1.12', '10.7.104.12'],
    "Which IP addresses participate in mission called Admin Services - BT2?": ['10.7.102.47', '10.2.4.47', '10.7.102.46', '10.2.4.46', '10.2.4.49', '10.7.102.49', '10.2.4.48', '10.7.102.48'],
    "Which CVE vulnerabilities are present on a host with IP address 10.4.1.12?": [],
    "Which CVE vulnerabilities are present on a host with IP address 10.3.1.14?": ['CVE-2020-0607', 'CVE-2022-21893', 'CVE-2020-17087', 'CVE-2025-53148', 'CVE-2025-32715', 'CVE-2025-24072', 'CVE-2025-21251', 'CVE-2025-21189', 'CVE-2024-43541', 'CVE-2024-38050', 'CVE-2024-26242', 'CVE-2023-50387', 'CVE-2024-21311', 'CVE-2024-20652', 'CVE-2023-36574', 'CVE-2023-33172', 'CVE-2022-35743', 'CVE-2023-28266', 'CVE-2023-21811', 'CVE-2023-21524', 'CVE-2022-41090', 'CVE-2022-34718', 'CVE-2022-29120', 'CVE-2022-23290', 'CVE-2022-21833', 'CVE-2021-42282', 'CVE-2021-31974', 'CVE-2021-24103', 'CVE-2021-1637', 'CVE-2020-16940', 'CVE-2020-1379', 'CVE-2020-1141', 'CVE-2020-0781'],
    "Which CVE vulnerabilities are present on a host with IP address 4.122.55.2?": ['CVE-2020-14415', 'CVE-2023-5536'],
    "Which hosts are jeopardized by lateral movement from IP address 10.6.1.12? Provide IP addresses of such hosts.": ['4.122.55.5', '10.7.100.5', '4.122.55.216', '4.122.55.3', '10.7.100.3'],
    "Which hosts are jeopardized by lateral movement from IP address 10.1.4.42? Provide IP addresses of such hosts.": ['4.122.55.2', '10.7.100.2', '4.122.55.21', '10.7.100.21', '4.122.55.117', '10.7.100.117', '4.122.55.111'],
    "Which hosts are jeopardized by lateral movement from IP address 10.1.2.23? Provide IP addresses of such hosts.": [],
    # prioritization
    "Which of CVE vulnerabilities: CVE-2020-14415, CVE-2015-5600, CVE-2022-21893 has the highest priority if you consider CVSS of version 2 and jeopardized Host entities from the database?": ["CVE-2022-21893"],
    "Which of CVE vulnerabilities: CVE-2020-1379, CVE-2020-1141, CVE-2016-10009 has the highest priority if you consider CVSS of version 2 and jeopardized Host entities from the database?": ["CVE-2020-1379"],
    "Which of CVE vulnerabilities: CVE-2007-3205, CVE-2021-1637, CVE-2020-0781 has the highest priority if you consider CVSS of version 2 and jeopardized Host entities from the database?": ["CVE-2020-0781"],
    "Which of CVE vulnerabilities: CVE-2015-6564, CVE-2023-34367, CVE-2020-0607 has the highest priority if you consider jeopardized Mission entities from the database?": ["CVE-2020-0607"],
    "Which of CVE vulnerabilities: CVE-2015-5600, CVE-2022-21893, CVE-2021-1637 has the highest priority if you consider jeopardized Mission entities from the database?": ["CVE-2022-21893"],
    "Which of CVE vulnerabilities: CVE-2022-29120, CVE-2023-21524, CVE-2019-19271 has the highest priority if you consider jeopardized Mission entities from the database?": ["CVE-2023-21524"]
}

# this part checks for alternatives when LLM used subnets instead of direct communication
LATERAL_MOVEMENT_ALTERNATIVES = {
    "Which hosts are jeopardized by lateral movement from IP address 10.6.1.12? Provide IP addresses of such hosts.": ["10.6.1.14", "10.6.1.13"],
    "Which hosts are jeopardized by lateral movement from IP address 10.1.4.42? Provide IP addresses of such hosts.": ["10.1.4.46", "10.1.4.43", "10.1.4.49", "10.1.4.44", "10.1.4.45", "10.1.4.48", "10.1.4.47"],
    "Which hosts are jeopardized by lateral movement from IP address 10.1.2.23? Provide IP addresses of such hosts.": ["10.1.2.24", "10.1.2.22", "10.1.2.29", "10.1.2.28", "10.1.2.27", "10.1.2.25", "10.1.2.26"],
}

questions_wrong_dictionary = {}
for question in QUESTIONS:
    questions_wrong_dictionary[question] = {"count": 0}


def test_models_and_settings(api_token=None):
    models = ["gpt-oss-120b", "qwen3-coder", "deepseek-v3.2-thinking"]
    temperatures = [(0.1, 0.3), (0.3, 0.5), (0.5, 0.8)]

    service = get_vulnllama_service()

    with (open("results.jsonl", "w", encoding="utf-8") as results_file):
        for query_model in models:
            for response_model in models:
                for temperature_pair in temperatures:
                    query_temperature = temperature_pair[0]
                    human_temperature = temperature_pair[1]

                    service._openai_config.query_model = query_model
                    service._openai_config.response_model = response_model
                    service._openai_config.query_builder_temperature = query_temperature
                    service._openai_config.human_transformer_temperature = human_temperature

                    for question in QUESTIONS:
                        post_question = {"question": question}
                        start_time = time()
                        response_json = service.answer(post_question["question"])
                        end_time = time()
                        measured_time = end_time - start_time
                        print(
                            f"Query model: {service._openai_config.query_model}, response model: {service._openai_config.response_model}, "
                            f"query temp: {service._openai_config.query_builder_temperature}, human temperature: {service._openai_config.human_transformer_temperature}")
                        response_json["time"] = measured_time
                        response_json["query_model"] = query_model
                        response_json["response_model"] = response_model
                        response_json["query_builder_temperature"] = query_temperature
                        response_json["human_transformer_temperature"] = human_temperature
                        results_file.write(json.dumps(response_json) + "\n")
                        print(response_json, "\n")


def analyze_result_json(file_path="results.jsonl"):
    # Analyze according to temperatures
    results_temperatures = {(0.1, 0.3): {"time_count": 0, "time_sum": 0.0, "average_time": 0.0},
                            (0.3, 0.5): {"time_count": 0, "time_sum": 0.0, "average_time": 0.0},
                            (0.5, 0.8): {"time_count": 0, "time_sum": 0.0, "average_time": 0.0}}
    with open(file_path, mode="r", encoding="utf-8") as results_file:
        for line in results_file:
            json_data = json.loads(line)
            query_builder_temperature = json_data["query_builder_temperature"]
            human_transformer_temperature = json_data["human_transformer_temperature"]
            results_temperatures[(query_builder_temperature, human_transformer_temperature)]["time_count"] += 1
            results_temperatures[(query_builder_temperature, human_transformer_temperature)]["time_sum"] += json_data["time"]
    for temperature_pair_string in results_temperatures:
        if results_temperatures[temperature_pair_string]["time_count"] != 0:
            results_temperatures[temperature_pair_string][
                "average_time"] = results_temperatures[temperature_pair_string]["time_sum"] / results_temperatures[
                temperature_pair_string]["time_count"]
    print("\n")
    print("Result temperatures:")
    pprint(results_temperatures)

    # The structure is: "query_model" is key, which contains a list of key-value items, where response_model is key
    results_models = {}
    with open(file_path, "r", encoding="utf-8") as results_file:
        for line in results_file:
            json_data = json.loads(line)
            if json_data["query_model"] not in results_models:
                results_models[json_data["query_model"]] = {}
            if json_data["response_model"] not in results_models[json_data["query_model"]]:
                results_models[json_data["query_model"]][json_data["response_model"]] = {}
            temperature_pair = (json_data["query_builder_temperature"], json_data["human_transformer_temperature"])
            if temperature_pair not in results_models[json_data["query_model"]][json_data["response_model"]]:
                results_models[json_data["query_model"]][json_data["response_model"]][temperature_pair] = {
                    "adherence_count": 0,
                    "adherence_sum": 0,
                    "adherence_average": 0}
            if check_adherence(json_data["human_result"]):
                results_models[json_data["query_model"]][json_data["response_model"]][temperature_pair]["adherence_count"] += 1
                results_models[json_data["query_model"]][json_data["response_model"]][temperature_pair]["adherence_sum"] += 1
            else:
                results_models[json_data["query_model"]][json_data["response_model"]][temperature_pair]["adherence_count"] += 1

    for query_model in results_models:
        for response_model in results_models[query_model]:
            for temperature_pair in results_models[query_model][response_model]:
                if results_models[query_model][response_model][temperature_pair]["adherence_count"] != 0:
                    results_models[query_model][response_model][temperature_pair][
                        "adherence_average"] = results_models[query_model][response_model][temperature_pair]["adherence_sum"] / results_models[
                        query_model][response_model][temperature_pair]["adherence_count"]

    print("\n")
    print("Result models:")
    pprint(results_models)

    results_times = {}
    with open(file_path, "r", encoding="utf-8") as results_file:
        for line in results_file:
            json_data = json.loads(line)
            if json_data["query_model"] not in results_times:
                results_times[json_data["query_model"]] = {}
            if json_data["response_model"] not in results_times[json_data["query_model"]]:
                results_times[json_data["query_model"]][json_data["response_model"]] = {"time_count": 0, "time_sum": 0.0, "time_average": 0.0}
            results_times[json_data["query_model"]][json_data["response_model"]]["time_count"] += 1
            results_times[json_data["query_model"]][json_data["response_model"]]["time_sum"] += json_data["time"]

    for query_model in results_times:
        for response_model in results_times[query_model]:
            if results_times[query_model][response_model]["time_count"] != 0:
                results_times[query_model][response_model]["time_average"] += results_times[query_model][response_model]["time_sum"] / results_times[query_model][response_model]["time_count"]
    pprint(results_times)

    results_correctness = {}
    with open(file_path, "r", encoding="utf-8") as results_file:
        for line in results_file:
            json_data = json.loads(line)
            if json_data["query_model"] not in results_correctness:
                results_correctness[json_data["query_model"]] = {}
            if json_data["response_model"] not in results_correctness[json_data["query_model"]]:
                results_correctness[json_data["query_model"]][json_data["response_model"]] = {}
            temperature_pair = (json_data["query_builder_temperature"], json_data["human_transformer_temperature"])
            if temperature_pair not in results_correctness[json_data["query_model"]][json_data["response_model"]]:
                results_correctness[json_data["query_model"]][json_data["response_model"]][temperature_pair] = {
                    "count": 0,
                    "sum": 0
                }
            results_correctness[json_data["query_model"]][json_data["response_model"]][temperature_pair]["count"] += 1
            results_correctness[json_data["query_model"]][json_data["response_model"]][temperature_pair]["sum"] += int(check_correctness(json_data))
    pprint(results_correctness)
    pprint(questions_wrong_dictionary)


def check_adherence(human_explanation):
    # check formatting of human explanation
    if not ("**Result:**" in human_explanation and "**Data:**" in human_explanation and "**Explanation:**" in human_explanation):
        # print(human_explanation)
        # print("first condition")
        return False

    # check no pre-amble
    if not human_explanation.startswith("**Result:**"):
        # print(human_explanation)
        # print("second condition")
        return False

    # count number of sentences
    sentences = len(re.findall(r"\. [A-Z]", human_explanation))
    if human_explanation.endswith("."):
        sentences += 1

    # Required 2-3 sentences, extended condition from 2 - 3 to 1 - 4 sentences
    if sentences not in [1, 2, 3, 4]:
        # print(human_explanation)
        # print("third condition")
        return False

    data_index = human_explanation.find("**Data:**")
    explanation_index = human_explanation.find("**Explanation:**")
    data_lines = human_explanation[data_index:explanation_index].split("\n")

    # formatting with newlines
    if len(data_lines) < 3:
        # print(human_explanation)
        # print("fourth condition")
        return False

    # format of table
    if "|" not in data_lines[1]:
        if "---" not in data_lines[2]:
            # print(human_explanation)
            # print("fifth condition")
            return False

    return True


def check_correctness(json_line):
    # Print statements in this procedure were used to output all LLM mistakes
    questions_ip_dictionary = {
        r"Which IP addresses communicated with IP address (?P<ip_address>.+?)\?": [
            "MATCH (ip1:IP {address: $ip_address)<-[:HAS_ASSIGNED]-(n1:Node)-[:IS_CONNECTED_TO]-(n2:Node)-[:HAS_ASSIGNED]-(ip2:IP) RETURN DISTINCT ip2.address"
        ],
        r"Which IP addresses participate in mission called (?P<mission_name>.+)\?": [
            "MATCH (m:Mission {name: $mission_name})<-[:SUPPORTS]-(c:Component)-[:PROVIDED_BY]->(h:Host)<-[:IS_A]-(n:Node)-[:HAS_ASSIGNED]->(ip:IP) RETURN DISTINCT ip.address"
        ],
        r"Which hosts are jeopardized by lateral movement from IP address (?P<ip_address>.+)\? Provide IP addresses of such hosts\.": [
            "MATCH (ip1:IP {address: $ip_address})<-[:HAS_ASSIGNED]-(n1:Node)-[:IS_CONNECTED_TO]-(n2:Node)-[:HAS_ASSIGNED]-(ip2:IP) RETURN DISTINCT ip2.address",
            "MATCH (ip1:IP {address: $ip_address})-[:PART_OF]->(:Subnet)<-[:PART_OF]-(ip2:IP) RETURN DISTINCT ip2.address"
        ],
    }

    questions_cve_dictionary = {
        r"Which CVE vulnerabilities are present on a host with IP address (?P<ip_address>.+)\?": [
            "MATCH (cve:CVE)<-[:REFERS_TO]-(v:Vulnerability)-[:IN]->(:SoftwareVersion)-[:ON]->(h:Host)<-[:IS_A]-(n:Node)-[:HAS_ASSIGNED]->(ip:IP {address: $ip_address}) RETURN DISTINCT cve.cve_id, cve.description"],
        r"Which of CVE vulnerabilities:": [
            "MATCH (cvss:CVSSv2)<-[:HAS_CVSS_v2]-(cve:CVE)<-[:REFERS_TO]-(v:Vulnerability)-[:IN]->(:SoftwareVersion)-[:ON]->(h:Host) WITH cvss.base_score AS base_score, COUNT(DISTINCT h) AS count_h, cve.cve_id AS cve_id, cve.description AS description RETURN cve_id, description, base_score * count_h AS final_score ORDER BY final_score DESC",
            "MATCH (m:Mission)<-[:SUPPORTS]-(c:Component)-[:PROVIDED_BY]->(h:Host)<-[:ON]-(:SoftwareVersion)<-[:IN]-(v:Vulnerability)-[:REFERS_TO]->(cve:CVE) RETURN cve.cve_id, cve.description, SUM(m.criticality) AS final_score ORDER BY final_score DESC"
        ]
    }

    for question in ANSWERS:
        if question == json_line["question"]:
            found = False
            for question_pattern in questions_ip_dictionary:
                if re.match(question_pattern, json_line["question"]):
                    if re.search(r"<.+?='(?P<ip_address>[\d\.]+?)'>", json_line["result"]):
                        found = True
                        results_list = re.findall(r"<.+?='(?P<ip_address>[\d\.]+?)'>", json_line["result"])
                        if sorted(ANSWERS[question]) != sorted(results_list) and not ("lateral movement" in json_line["question"] and (
                                (set(ANSWERS[question]).issubset(set(results_list)) and ("*1..]" in json_line["query"] or "*]" in json_line["query"])) or sorted(
                            results_list) == sorted(LATERAL_MOVEMENT_ALTERNATIVES[question]) or (
                                set(LATERAL_MOVEMENT_ALTERNATIVES[question]).issubset(set(results_list)) and ("*1..]" in json_line["query"] or "*]" in json_line["query"])))):
                            questions_wrong_dictionary[question]["count"] += 1
                            # print(json_line["question"])
                            # print(json_line["query"])
                            # print(json_line["result"])
                            # print(sorted(results_list))
                            # print(sorted(ANSWERS[question]))
                            # print()
                        return sorted(ANSWERS[question]) == sorted(results_list) or ("lateral movement" in json_line["question"] and (set(ANSWERS[question]).issubset(set(results_list)) or sorted(results_list) == sorted(LATERAL_MOVEMENT_ALTERNATIVES[question]) or set(LATERAL_MOVEMENT_ALTERNATIVES[question]).issubset(set(results_list))))
                    elif json_line["result"] == "":
                        found = True
                        if ANSWERS[question] != []:
                            questions_wrong_dictionary[question]["count"] += 1
                            # print(json_line["question"])
                            # print(json_line["query"])
                            # print(json_line["result"])
                            # print(ANSWERS[question])
                            # print()
                        return ANSWERS[question] == []
            for question_pattern in questions_cve_dictionary:
                if re.match(question_pattern, json_line["question"]):
                    if re.search(r"(?P<cve_id>'CVE-\d{4}-\d+?')", json_line["result"]):
                        found = True
                        results_list = re.findall(r"'(?P<cve_id>CVE-\d{4}-\d+?)'", json_line["result"])
                        if sorted(ANSWERS[question]) != sorted(results_list):
                            questions_wrong_dictionary[question]["count"] += 1
                            # print(json_line["question"])
                            # print(json_line["query"])
                            # print(json_line["result"])
                            # print(sorted(results_list))
                            # print(sorted(ANSWERS[question]))
                            # print()
                        return sorted(ANSWERS[question]) == sorted(results_list)
                    elif json_line["result"] == "":
                        found = True
                        if ANSWERS[question] != []:
                            questions_wrong_dictionary[question]["count"] += 1
                            # print(json_line["question"])
                            # print(json_line["query"])
                            # print(json_line["result"])
                            # print(ANSWERS[question])
                            # print()
                        return ANSWERS[question] == []
            if not found:
                questions_wrong_dictionary[question]["count"] += 1
                # print("NOT FOUND")
                # print(json_line["question"])
                # print(json_line["result"])
                # print()

    return False
