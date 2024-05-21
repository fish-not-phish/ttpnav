import unittest
from ttpnav import MitreData

class TestMitreData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mitre_data = MitreData()

    def test_get_technique_by_attack_id(self):
        technique_id = "T1134"
        technique = self.mitre_data.get_technique(technique_id)
        self.assertIsNotNone(technique)
        self.assertIsNotNone(technique.id)
        self.assertIsNotNone(technique.name)
        self.assertIsNotNone(technique.description)

        print(f"External ID: {technique.external_id}")
        print(f"Technique Name: {technique.name}")
        print(f"Technique Description: {technique.description}\n")
        for m in technique.mitigations:
            print(f"External ID: {m.external_id}")
            print(f"Mitigation Keys: {m.__dict__.keys()}\n")
            break
        for d in technique.detections:
            print(f"Detection External ID: {d.external_id}")
            print(f"Detection Keys: {d.__dict__.keys()}\n")
            break
        for pe in technique.procedureExamples:
            print(f"Procedure Example Keys: {pe.__dict__.keys()}\n")
            break
        for g in technique.groups:
            print(f"Group Example Keys: {g.__dict__.keys()}\n")
            break
        for s in technique.softwares:
            print(f"Software Example Keys: {s.__dict__.keys()}\n")
            break

    def test_get_tool(self):
        tool = self.mitre_data.get_tool('S0039')
        self.assertIsNotNone(tool.id)
        self.assertIsNotNone(tool.name)
        self.assertIsNotNone(tool.description)

        print(f"External ID: {tool.external_id}")
        print(f"Tool Name: {tool.name}")
        print(f"Description: {tool.description}\n")
        for group in tool.groups:
            print(group.name)
        for technique in tool.techniques:
            print("technique")
            for pe in technique.procedureExamples:
                
                print(pe.source_attack_id)
                print(pe.description)

    def test_get_tools(self):
        tools = self.mitre_data.get_tools()
        self.assertTrue(len(tools) > 0)
        for tool in tools:
            self.assertIsNotNone(tool.id)
            self.assertIsNotNone(tool.name)
            self.assertIsNotNone(tool.description)

            print(f"External ID: {tool.external_id}")
            print(f"Tool Name: {tool.name}")
            print(f"Description: {tool.description}\n")
            for group in tool.groups:
                print(group.name)
            for technique in tool.techniques:
                print("technique")
                for pe in technique.procedureExamples:
                    
                    print(pe.source_attack_id)
                    print(pe.description)
            break

    def test_get_groups(self):
        groups = self.mitre_data.get_groups()
        self.assertTrue(len(groups) > 0)
        for group in groups:
            self.assertIsNotNone(group.id)
            self.assertIsNotNone(group.name)
            self.assertIsNotNone(group.description)

            print(f"External ID: {group.external_id}")
            print(f"Group Name: {group.name}")
            print(f"Description: {group.description}\n")
            print(f"{group.__dict__.keys()}\n")
            for technique in group.techniques:
                print("technique")
                for pe in technique.procedureExamples:
                    
                    print(pe.source_attack_id)
                    print(pe.description)
            break

    def test_get_tactics(self):
        tactics = self.mitre_data.get_tactics()
        self.assertTrue(len(tactics) > 0)
        for tactic in tactics:
            self.assertIsNotNone(tactic.id)
            self.assertIsNotNone(tactic.name)
            self.assertIsNotNone(tactic.description)

            print(f"External ID: {tactic.external_id}")
            print(f"Tactic Name: {tactic.name}")
            print(f"Description: {tactic.description}\n")
            print(f"{tactic.__dict__.keys()}\n")

    def test_get_techniques(self):
        techniques = self.mitre_data.get_parent_techniques()
        self.assertTrue(len(techniques) > 0)
        for technique in techniques:
            self.assertIsNotNone(technique.id)
            self.assertIsNotNone(technique.name)
            self.assertIsNotNone(technique.description)

            print(f"External ID: {technique.external_id}")
            print(f"Technique Keys: {technique.__dict__.keys()}\n")
            for m in technique.mitigations:
                print(f"External ID: {m.external_id}")
                print(f"Mitigation Keys: {m.__dict__.keys()}\n")
                break
            for d in technique.detections:
                print(f"Detection External ID: {d.external_id}")
                print(f"Detection Keys: {d.__dict__.keys()}\n")
                break
            for pe in technique.procedureExamples:
                print(f"Procedure Example Keys: {pe.__dict__.keys()}\n")
                print(pe.description)
                break
            for g in technique.groups:
                print(f"Group Example Keys: {g.__dict__.keys()}\n")
                break
            for s in technique.softwares:
                print(f"Software Example Keys: {s.__dict__.keys()}\n")
                break
            break


    def test_get_subtechniques(self):
        subtechniques = self.mitre_data.get_subtechniques()
        self.assertTrue(len(subtechniques) > 0)
        for subtechnique in subtechniques:
            self.assertIsNotNone(subtechnique.id)
            self.assertIsNotNone(subtechnique.name)
            self.assertIsNotNone(subtechnique.description)

            print(f"External ID: {subtechnique.external_id}")
            print(f"Subtechnique Keys: {subtechnique.__dict__.keys()}\n")
            print(f"Parent ID: {subtechnique.parent_external_id}")
            for m in subtechnique.mitigations:
                print(f"External ID: {m.external_id}")
                print(f"Mitigation Keys: {m.__dict__.keys()}\n")
                break
            for d in subtechnique.detections:
                print(f"Detection External ID: {d.external_id}")
                print(f"Detection Keys: {d.__dict__.keys()}\n")
                break
            for pe in subtechnique.procedureExamples:
                print(f"Procedure Example Keys: {pe.__dict__.keys()}\n")
                print(pe.description)
                break
            for g in subtechnique.groups:
                print(f"Group Example Keys: {g.__dict__.keys()}\n")
                break
            for s in subtechnique.softwares:
                print(f"Software Example Keys: {s.__dict__.keys()}\n")
                break
            break

if __name__ == '__main__':
    unittest.main()