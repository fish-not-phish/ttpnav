from mitreattack.stix20 import MitreAttackData
import json
import os
import requests

MITRE_ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_ATTACK_JSON_PATH = "enterprise-attack.json"

class Tactic:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.external_id = mitre_attack_data.get_attack_id(self.id)

class Technique:
    def __init__(self, mitre_attack_data, parent_external_id=None, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.external_id = mitre_attack_data.get_attack_id(self.id)
        self.mitigations = kwargs.get("mitigations", [])
        self.parent_external_id = parent_external_id
        self.detections = kwargs.get("detections", [])
        self.procedureExamples = kwargs.get("procedureExamples", [])
        self.groups = kwargs.get("groups", [])
        self.softwares = kwargs.get("softwares", [])

class Mitigation:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.external_id = mitre_attack_data.get_attack_id(self.id)

class Detection:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        datasource = mitre_attack_data.get_object_by_stix_id(self.x_mitre_data_source_ref)
        self.external_id = mitre_attack_data.get_attack_id(datasource.id)

class ProcedureExample:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        source_object = mitre_attack_data.get_object_by_stix_id(self.source_ref)
        attack_id = mitre_attack_data.get_attack_id(source_object.id)
        self.source_attack_id = attack_id

class Group:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.external_id = mitre_attack_data.get_attack_id(self.id)

class GroupDetail:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.external_id = mitre_attack_data.get_attack_id(self.id)
        self.techniques = kwargs.get("techniques", [])
        self.softwares = kwargs.get("softwares", [])
        self.techniques = self.filter_technique_procedure_examples(kwargs.get("techniques", []))

    def filter_technique_procedure_examples(self, techniques):
        for technique in techniques:
            technique.procedureExamples = [example for example in technique.procedureExamples if example.source_attack_id == self.external_id]
        return techniques
    
class SoftwareDetail:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.external_id = mitre_attack_data.get_attack_id(self.id)
        self.techniques = kwargs.get("techniques", [])
        self.groups = kwargs.get("groups", [])
        self.techniques = self.filter_technique_procedure_examples(kwargs.get("techniques", []))

    def filter_technique_procedure_examples(self, techniques):
        for technique in techniques:
            technique.procedureExamples = [example for example in technique.procedureExamples if example.source_attack_id == self.external_id]
        return techniques

class Software:
    def __init__(self, mitre_attack_data, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.external_id = mitre_attack_data.get_attack_id(self.id)

class MitreData:
    def __init__(self):
        self.file_path = self.download_mitre_attack_data(MITRE_ATTACK_JSON_PATH)
        self.mitre_attack_data = MitreAttackData(self.file_path)

    @staticmethod
    def download_mitre_attack_data(file_path):
        if not os.path.exists(file_path):
            print("Downloading MITRE ATT&CK data...")
            response = requests.get(MITRE_ATTACK_JSON_URL)
            with open(file_path, 'wb') as file:
                file.write(response.content)
            print("Download complete.")
        return file_path

    def get_groups(self):
        groups = self.mitre_attack_data.get_groups(remove_revoked_deprecated=True)
        group_objects = []
        for group in groups:
            techniques = self.get_techniques_used_by_group(group.id)
            softwares = self.get_software_used_by_group(group.id)
            group_obj = GroupDetail(self.mitre_attack_data, techniques=techniques, softwares=softwares, **group)
            group_objects.append(group_obj)
        return group_objects
    
    def get_group(self, attack_id):
        group = self.mitre_attack_data.get_object_by_attack_id(attack_id, "intrusion-set")
        if group:
            techniques = self.get_techniques_used_by_group(group.id)
            softwares = self.get_software_used_by_group(group.id)
            group_obj = GroupDetail(self.mitre_attack_data, techniques=techniques, softwares=softwares, **group)
            return group_obj
        return None
    
    def get_technique(self, attack_id):
        technique = self.mitre_attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
        if technique:
            mitigations = self.get_mitigations_from_technique(technique.id)
            detections = self.get_technique_detections(technique.id)
            procedureExamples = self.get_procedure_examples_from_technique(technique.id)
            groups = self.get_groups_using_technique(technique.id)
            softwares = self.get_software_using_technique(technique.id)
            technique_obj = Technique(self.mitre_attack_data, mitigations=mitigations, detections=detections, procedureExamples=procedureExamples, groups=groups, softwares=softwares, **technique)
            return technique_obj
        return None

    def get_tactics(self):
        tactics = self.mitre_attack_data.get_tactics(remove_revoked_deprecated=True)
        return [Tactic(self.mitre_attack_data, **tactic) for tactic in tactics]
    
    def get_tools(self):
        softwares = self.mitre_attack_data.get_software(remove_revoked_deprecated=True)
        tool_objects = []
        for tool in softwares:
            techniques = self.get_techniques_used_by_software(tool.id)
            groups = self.get_groups_using_software(tool.id)
            tool_obj = SoftwareDetail(self.mitre_attack_data, techniques=techniques, groups=groups, **tool)
            tool_objects.append(tool_obj)
        return tool_objects
    
    def get_tool(self, attack_id):
        tool = self.mitre_attack_data.get_object_by_attack_id(attack_id, "tool")
        if tool:
            techniques = self.get_techniques_used_by_software(tool.id)
            groups = self.get_groups_using_software(tool.id)
            tool_obj = SoftwareDetail(self.mitre_attack_data, techniques=techniques, groups=groups, **tool)
            return tool_obj
        return None

    def get_groups_using_software(self, software_id):
        groups = self.mitre_attack_data.get_groups_using_software(software_id)
        return [Group(self.mitre_attack_data, **group["object"]) for group in groups]

    def get_parent_techniques(self):
        techniques = self.mitre_attack_data.get_techniques(include_subtechniques=False, remove_revoked_deprecated=True)
        technique_objects = []
        for technique in techniques:
            mitigations = self.get_mitigations_from_technique(technique.id)
            detections = self.get_technique_detections(technique.id)
            procedureExamples = self.get_procedure_examples_from_technique(technique.id)
            groups = self.get_groups_using_technique(technique.id)
            softwares = self.get_software_using_technique(technique.id)
            technique_obj = Technique(self.mitre_attack_data, mitigations=mitigations, detections=detections, procedureExamples=procedureExamples, groups=groups, softwares=softwares, **technique)
            technique_objects.append(technique_obj)
        return technique_objects
    
    def get_subtechniques(self):
        subtechniques = self.mitre_attack_data.get_subtechniques(remove_revoked_deprecated=True)
        subtechnique_objects = []
        for subtechnique in subtechniques:
            mitigations = self.get_mitigations_from_technique(subtechnique.id)
            detections = self.get_technique_detections(subtechnique.id)
            procedureExamples = self.get_procedure_examples_from_technique(subtechnique.id)
            groups = self.get_groups_using_technique(subtechnique.id)
            softwares = self.get_software_using_technique(subtechnique.id)

            parent_technique = self.mitre_attack_data.get_parent_technique_of_subtechnique(subtechnique.id)
            parent_external_id = self.mitre_attack_data.get_attack_id(parent_technique[0]["object"].id) if parent_technique else None

            subtechnique_obj = Technique(self.mitre_attack_data, mitigations=mitigations, detections=detections, procedureExamples=procedureExamples, groups=groups, softwares=softwares, parent_external_id=parent_external_id, **subtechnique)
            subtechnique_objects.append(subtechnique_obj)
        return subtechnique_objects
    
    def get_techniques_used_by_software(self, software_id):
        techniques = self.mitre_attack_data.get_techniques_used_by_software(software_id)
        technique_objects = []
        for t in techniques:
            technique = t["object"]
            mitigations = self.get_mitigations_from_technique(technique.id)
            detections = self.get_technique_detections(technique.id)
            procedureExamples = self.get_procedure_examples_from_technique(technique.id)
            technique_obj = Technique(self.mitre_attack_data, mitigations=mitigations, detections=detections, procedureExamples=procedureExamples, **technique)
            technique_objects.append(technique_obj)
        return technique_objects
    
    def get_mitigations_from_technique(self, technique_id):
        mitigations = self.mitre_attack_data.get_mitigations_mitigating_technique(technique_id)
        return [Mitigation(self.mitre_attack_data, **mitigation["object"]) for mitigation in mitigations]
    
    def get_technique_detections(self, technique_id):
        detections = self.mitre_attack_data.get_datacomponents_detecting_technique(technique_id)
        return [Detection(self.mitre_attack_data, **detection["object"]) for detection in detections]
    
    def get_procedure_examples_from_technique(self, technique_id):
        procedure_examples = self.mitre_attack_data.get_procedure_examples_by_technique(technique_id)
        return [ProcedureExample(self.mitre_attack_data, **procedure_example) for procedure_example in procedure_examples]
    
    def get_groups_using_technique(self, technique_id):
        groups = self.mitre_attack_data.get_groups_using_technique(technique_id)
        return [Group(self.mitre_attack_data, **group["object"]) for group in groups]
    
    def get_software_using_technique(self, technique_id):
        softwares = self.mitre_attack_data.get_software_using_technique(technique_id)
        return [Software(self.mitre_attack_data, **software["object"]) for software in softwares]
    
    def get_software_used_by_group(self, group_id):
        softwares = self.mitre_attack_data.get_software_used_by_group(group_id)
        return [Software(self.mitre_attack_data, **software["object"]) for software in softwares]
    
    def get_techniques_used_by_group(self, group_id):
        techniques = self.mitre_attack_data.get_techniques_used_by_group(group_id)
        technique_objects = []
        for t in techniques:
            technique = t["object"]
            mitigations = self.get_mitigations_from_technique(technique.id)
            detections = self.get_technique_detections(technique.id)
            procedureExamples = self.get_procedure_examples_from_technique(technique.id)
            technique_obj = Technique(self.mitre_attack_data, mitigations=mitigations, detections=detections, procedureExamples=procedureExamples, **technique)
            technique_objects.append(technique_obj)
        return technique_objects
    