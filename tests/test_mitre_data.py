import unittest
from ttpnav import MitreData

class TestMitreData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mitre_data = MitreData()

    def test_get_technique_by_attack_id(self):
        technique_id = "T1134"
        technique = self.mitre_data.get_technique(technique_id)
        print(f"Name: {technique.name}")
        print(f"Description: {technique.description}")
        print(f"STIX ID: {technique.id}")
        print(f"Associated Mitigations (dictionary): {technique.mitigations}")
        print(f"Associated Detections (dictionary): {technique.detections}")
        print(f"Associated Procedure Examples (dictionary): {technique.procedureExamples}")
        print(f"Associated Groups (dictionary): {technique.groups}")
        print(f"Associated Tools (dictionary): {technique.softwares}")
        print(f"MITRE Attack ID: {technique.external_id}")
        print(f"Parent Technique MITRE Attack ID: {technique.parent_external_id}")
        print(f"All Available Keys: {technique.__dict__.keys()}\n")
        
        # To access the dictionaries of the technique
        # I only wrote examples of how to access the common dictionary items
        # Please explore the rest of the keys in "All Available Keys" to understand the available data
        for mitigation in technique.mitigations:
            print(f"Name: {mitigation.name}")
            print(f"Description: {mitigation.description}")
            print(f"STIX ID: {mitigation.id}")
            print(f"MITRE Attack ID: {technique.external_id}")
            print(f"All Available Mitigation Keys: {mitigation.__dict__.keys()}\n")
        for detection in technique.detections:
            print(f"Name: {detection.name}")
            print(f"Description: {detection.description}")
            print(f"STIX ID: {detection.id}")
            print(f"MITRE Attack ID: {detection.external_id}")
            print(f"All Available Detection Keys: {detection.__dict__.keys()}\n")
        for example in technique.procedureExamples:
            print(f"Related Group/Tool MITRE Attack ID: {example.source_attack_id}")
            print(f"Relationship Type: {example.relationship_type}")
            print(f"Description: {example.description}")
            print(f"All Available Procedure Example Keys: {example.__dict__.keys()}\n")
        for group in technique.groups:
            print(f"Name: {group.name}")
            print(f"Aliases: {group.aliases}")
            print(f"Description: {group.description}")
            print(f"STIX ID: {group.id}")
            print(f"MITRE Attack ID: {group.external_id}")
            print(f"Group Example Keys: {group.__dict__.keys()}\n")
        for tool in technique.softwares:
            print(f"Name: {tool.name}")
            print(f"Description: {tool.description}")
            print(f"STIX ID: {tool.id}")
            print(f"MITRE Attack ID: {tool.external_id}")
            print(f"Software Example Keys: {tool.__dict__.keys()}\n")


    def test_get_tool(self):
        tool = self.mitre_data.get_tool('S0039')
        print(f"Name: {tool.name}")
        print(f"Description: {tool.description}")
        print(f"STIX ID: {tool.id}")
        print(f"MITRE Attack ID: {tool.external_id}")
        print(f"Software Example Keys: {tool.__dict__.keys()}\n")
        for group in tool.groups:
            print(f"Name: {group.name}")
            print(f"Aliases: {group.aliases}")
            print(f"Description: {group.description}")
            print(f"STIX ID: {group.id}")
            print(f"MITRE Attack ID: {group.external_id}")
            print(f"Group Example Keys: {group.__dict__.keys()}\n")
        for technique in tool.techniques:
            print(f"Name: {technique.name}")
            print(f"Description: {technique.description}")
            print(f"STIX ID: {technique.id}")
            print(f"Associated Mitigations (dictionary): {technique.mitigations}")
            print(f"Associated Detections (dictionary): {technique.detections}")
            print(f"Associated Procedure Examples (dictionary): {technique.procedureExamples}")
            print(f"MITRE Attack ID: {technique.external_id}")
            print(f"Parent Technique MITRE Attack ID: {technique.parent_external_id}")
            print(f"All Available Technique Keys: {technique.__dict__.keys()}\n")
            # Example of getting Procedure Examples from technique
            # The same method should be used for other dictionaries
            for example in technique.procedureExamples:
                print(f"Related Group/Tool MITRE Attack ID: {example.source_attack_id}")
                print(f"Relationship Type: {example.relationship_type}")
                print(f"Description: {example.description}")
                print(f"All Available Procedure Example Keys: {example.__dict__.keys()}\n")

    def test_get_tools(self):
        tools = self.mitre_data.get_tools()
        for tool in tools:
            print(f"Name: {tool.name}")
            print(f"Description: {tool.description}")
            print(f"STIX ID: {tool.id}")
            print(f"MITRE Attack ID: {tool.external_id}")
            print(f"Software Example Keys: {tool.__dict__.keys()}\n")
            for group in tool.groups:
                print(f"Name: {group.name}")
                print(f"Aliases: {group.aliases}")
                print(f"Description: {group.description}")
                print(f"STIX ID: {group.id}")
                print(f"MITRE Attack ID: {group.external_id}")
                print(f"Group Example Keys: {group.__dict__.keys()}\n")
            for technique in tool.techniques:
                print(f"Name: {technique.name}")
                print(f"Description: {technique.description}")
                print(f"STIX ID: {technique.id}")
                print(f"Associated Mitigations (dictionary): {technique.mitigations}")
                print(f"Associated Detections (dictionary): {technique.detections}")
                print(f"Associated Procedure Examples (dictionary): {technique.procedureExamples}")
                print(f"MITRE Attack ID: {technique.external_id}")
                print(f"Parent Technique MITRE Attack ID: {technique.parent_external_id}")
                print(f"All Available Technique Keys: {technique.__dict__.keys()}\n")
                # Example of getting Procedure Examples from technique
                # The same method should be used for other dictionaries
                for example in technique.procedureExamples:
                    print(f"Related Group/Tool MITRE Attack ID: {example.source_attack_id}")
                    print(f"Relationship Type: {example.relationship_type}")
                    print(f"Description: {example.description}")
                    print(f"All Available Procedure Example Keys: {example.__dict__.keys()}\n")

    def test_get_groups(self):
        groups = self.mitre_data.get_groups()
        for group in groups:
            print(f"External ID: {group.external_id}")
            print(f"Group Name: {group.name}")
            print(f"Description: {group.description}\n")
            print(f"{group.__dict__.keys()}\n")
            for technique in group.techniques:
                print(f"Name: {technique.name}")
                print(f"Description: {technique.description}")
                print(f"STIX ID: {technique.id}")
                print(f"Associated Mitigations (dictionary): {technique.mitigations}")
                print(f"Associated Detections (dictionary): {technique.detections}")
                print(f"Associated Procedure Examples (dictionary): {technique.procedureExamples}")
                print(f"MITRE Attack ID: {technique.external_id}")
                print(f"Parent Technique MITRE Attack ID: {technique.parent_external_id}")
                print(f"All Available Technique Keys: {technique.__dict__.keys()}\n")
                # Example of getting Procedure Examples from technique
                # The same method should be used for other dictionaries
                for example in technique.procedureExamples:
                    print(f"Related Group/Tool MITRE Attack ID: {example.source_attack_id}")
                    print(f"Relationship Type: {example.relationship_type}")
                    print(f"Description: {example.description}")
                    print(f"All Available Procedure Example Keys: {example.__dict__.keys()}\n")

    def test_get_tactics(self):
        tactics = self.mitre_data.get_tactics()
        for tactic in tactics:
            print(f"External ID: {tactic.external_id}")
            print(f"Tactic Name: {tactic.name}")
            print(f"Description: {tactic.description}\n")
            print(f"STIX ID: {tactic.id}")
            print(f"{tactic.__dict__.keys()}\n")

    def test_get_techniques(self):
        techniques = self.mitre_data.get_parent_techniques()
        for technique in techniques:
            print(f"External ID: {technique.external_id}")
            print(f"Technique Keys: {technique.__dict__.keys()}\n")
            for m in technique.mitigations:
                print(f"External ID: {m.external_id}")
                print(f"Mitigation Keys: {m.__dict__.keys()}\n")
            for d in technique.detections:
                print(f"Detection External ID: {d.external_id}")
                print(f"Detection Keys: {d.__dict__.keys()}\n")
            for pe in technique.procedureExamples:
                print(f"Procedure Example Keys: {pe.__dict__.keys()}\n")
                print(pe.description)
            for g in technique.groups:
                print(f"Group Example Keys: {g.__dict__.keys()}\n")
            for s in technique.softwares:
                print(f"Software Example Keys: {s.__dict__.keys()}\n")

    def test_get_subtechniques(self):
        subtechniques = self.mitre_data.get_subtechniques()
        for subtechnique in subtechniques:
            print(f"External ID: {subtechnique.external_id}")
            print(f"Subtechnique Keys: {subtechnique.__dict__.keys()}\n")
            print(f"Parent ID: {subtechnique.parent_external_id}")
            for m in subtechnique.mitigations:
                print(f"External ID: {m.external_id}")
                print(f"Mitigation Keys: {m.__dict__.keys()}\n")
            for d in subtechnique.detections:
                print(f"Detection External ID: {d.external_id}")
                print(f"Detection Keys: {d.__dict__.keys()}\n")
            for pe in subtechnique.procedureExamples:
                print(f"Procedure Example Keys: {pe.__dict__.keys()}\n")
                print(pe.description)
            for g in subtechnique.groups:
                print(f"Group Example Keys: {g.__dict__.keys()}\n")
            for s in subtechnique.softwares:
                print(f"Software Example Keys: {s.__dict__.keys()}\n")

if __name__ == '__main__':
    unittest.main()