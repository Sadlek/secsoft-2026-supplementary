# Supplementary Materials: Intelligence Augmentation in a Platform for Cyber Situational Awareness

These supplementary materials contain evaluation scripts used for computing results presented in the paper:
* `service_copy.py` which contains copy of conversational service from ISIM REST API, but which communicated with LLM directly without a REST API endpoint
* `testing_script.py` contains evaluation questions, results, and tests that were used to compute statistics from the paper.

In addition, it is necessary to set up two public components from the Resilmesh platform that contain the implemented functionality from the paper:
* ISIM component contains the new functionality in branch 65-vuln-ai at https://github.com/Sadlek/Resilmesh-ISIM/tree/65-vuln-ai
* SACD component contains the new functionality in branch vuln-ai at https://github.com/Sadlek/Resilmesh-SACD/tree/vuln-ai

In both cases, executing `docker compose up` according to instructions should be enough to set the conversation service. Endpoint for LLM is at port `8000` and dashboard panel for AI can be found in the dashboard's menu.

Due to using private cloud-based LLM, the components will not work completely without access to the LLM but user could provide own LLM's URL that adheres to OpenAI standards and own data to Neo4j database. In such a case, the functionality can be tested completely.