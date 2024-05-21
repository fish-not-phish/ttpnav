# ttpnav

A package to navigate MITRE ATT&CK data easily.

The inspiration of this Python library is to give users the ability to effortlessly comb through associated items with 1 query, instead of having to make the associations manually.

If a user wants to get information regarding a specific technique, then the user simply needs to use the MITRE Attack ID of the desired technique and all available MITRE CTI information will be available regarding that technique. This includes mitigations, detections, procedure examples, groups using the technique and software/tools using the technique. 

`Note: Some queries can take 1-2 minutes to complete.`

## Installation
To use this package, install the ttpnav Python library with pip:
```bash
pip install ttpnav
```
## Data Models
### Shared Keys
All objects should have the below shared data structure.

```yaml
Type                            :       type
Spec Version                    :       spec_version
STIX ID                         :       id
Created by Reference            :       created_by_ref
Created                         :       created
Modified                        :       modified
Revoked                         :       revoked
External References             :       external_references
Object Marking References       :       object_marking_refs
Name                            :       name
Description                     :       description
MITRE Attack Spec Version       :       x_mitre_attack_spec_version
MITRE Domains                   :       x_mitre_domains
MITRE Modified by References    :       x_mitre_modified_by_ref
MITRE Shortname                 :       x_mitre_shortname
MITRE Version                   :       x_mitre_version
MITRE Attack ID                 :       external_id
```
Some objects have additional items that can be referenced. These will be outlined below. The structure of the data allows users to get all associated entities to the item(s) they queried for. The associated data will be extended via additional dictionaries.
### Parent Technique(s)
```yaml
Mitigations                     :       mitigations (dict)
Detections                      :       detections (dict)
Procedure Examples              :       procedureExamples (dict)
Created by Reference            :       created_by_ref
Groups                          :       groups (dict)
Software                        :       softwares (dict)
Kill Chain Phases               :       kill_chain_phases
Is Subtechnique                 :       x_mitre_is_subtechnique
MITRE Platforms                 :       x_mitre_platforms
MITRE Remote Support            :       x_mitre_remote_support
Parent MITRE ATtack             :       parent_external_id (will be None)
```
### Subtechnique(s)

```yaml
Mitigations                     :       mitigations (dict)
Detections                      :       detections (dict)
Procedure Examples              :       procedureExamples (dict)
Created by Reference            :       created_by_ref
Groups                          :       groups (dict)
Software                        :       softwares (dict)
Kill Chain Phases               :       kill_chain_phases
Is Subtechnique                 :       x_mitre_is_subtechnique
MITRE Platforms                 :       x_mitre_platforms
MITRE Remote Support            :       x_mitre_remote_support
Parent MITRE ATtack             :       parent_external_id (will be None)
```
### Mitigation(s)
```yaml
Uses Shared Keys
```
### Detection(s)
```yaml
Uses Shared Keys
```
### Procedure Example(s)
```yaml
Relationship Type               :       relationship_type
Source Reference                :       source_ref
Target Reference                :       target_ref
```
### Group(s)
```yaml
Relationship Type               :       relationship_type
Source Reference                :       source_ref
Target Reference                :       target_ref
```
### Tool(s) / Software
```yaml
Techniques                      :       technuiques
Groups                          :       groups
Labels                          :       labels
```
## Usage / Examples
### Get Tactics (All)
```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    tactics = mitre_data.get_tactics()
    for tactic in tactics:
            print(f"External ID: {tactic.external_id}")
            print(f"Tactic Name: {tactic.name}")
            print(f"Description: {tactic.description}\n")
            print(f"{tactic.__dict__.keys()}\n")

if __name__ == "__main__":
    main()
```
### Get Parent Techniques (All Parent Techniques)
```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    techniques = mitre_data.get_parent_techniques()
    for technique in techniques:
            print(f"External ID: {technique.external_id}")
            print(f"Technique Keys: {technique.__dict__.keys()}\n")
            for m in technique.mitigations:
                print(f"Mitigation Keys: {m.__dict__.keys()}\n")
            for d in technique.detections:
                print(f"Detection Keys: {d.__dict__.keys()}\n")
            for example in technique.procedureExamples:
                print(f"Procedure Example Keys: {example.__dict__.keys()}\n")
            for g in technique.groups:
                print(f"Group Example Keys: {g.__dict__.keys()}\n")
            for s in technique.softwares:
                print(f"Software Example Keys: {s.__dict__.keys()}\n")

if __name__ == "__main__":
    main()
```
### Get Subtechniques (All)

```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    subtechniques = mitre_data.get_subtechniques()
    for subtechnique in subtechniques:
        print(f"External ID: {subtechnique.external_id}")
        print(f"Subtechnique Keys: {subtechnique.__dict__.keys()}\n")
        print(f"Parent ID: {subtechnique.parent_external_id}")
        for m in subtechnique.mitigations:
            print(f"Mitigation Keys: {m.__dict__.keys()}\n")
        for d in subtechnique.detections:
            print(f"Detection Keys: {d.__dict__.keys()}\n")
        for example in subtechnique.procedureExamples:
            print(f"Procedure Example Keys: {example.__dict__.keys()}\n")
        for g in subtechnique.groups:
            print(f"Group Example Keys: {g.__dict__.keys()}\n")
        for s in subtechnique.softwares:
            print(f"Software Example Keys: {s.__dict__.keys()}\n")

if __name__ == "__main__":
    main()
```
### Get Technique (Singular)
```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    technique_id = "T1134" # Add in your own MITRE Attack ID Here
    technique = mitre_data.get_technique(technique_id)
    
    if technique:
        print(f"External ID: {technique.external_id}")
        print(f"Technique Name: {technique.name}")
        print(f"Technique Description: {technique.description}\n")

        for m in technique.mitigations:
            print(f"Mitigation External ID: {m.external_id}")
            print(f"Mitigation Keys: {list(m.__dict__.keys())}\n")
            break

        for d in technique.detections:
            print(f"Detection External ID: {d.external_id}")
            print(f"Detection Keys: {list(d.__dict__.keys())}\n")
            break

        for pe in technique.procedureExamples:
            print(f"Procedure Example Keys: {list(pe.__dict__.keys())}\n")
            break

        for g in technique.groups:
            print(f"Group Keys: {list(g.__dict__.keys())}\n")
            break

        for s in technique.softwares:
            print(f"Software Keys: {list(s.__dict__.keys())}\n")
            break

if __name__ == "__main__":
    main()

```

### Get Tools/Software (All)
```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    tools = mitre_data.get_tools()
    for tool in tools:
        print(f"External ID: {tool.external_id}")
        print(f"Tool Name: {tool.name}")
        print(f"Description: {tool.description}\n")
        print(f"Tool Keys: {tool.__dict__.keys()}\n")
        for group in tool.groups:
            print(f"Group Keys: {group.__dict__.keys()}\n")
        for technique in tool.techniques:
            print(f"Technique Keys: {technique.__dict__.keys()}\n")
            for example in technique.procedureExamples:
                print(f"Procedure Example Keys: {example.__dict__.keys()}\n")

if __name__ == "__main__":
    main()
```
### Get Tool/Software (Singular)
```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    tool_id = "S0039" # Add in your own MITRE Attack ID Here
    tool = mitre_data.get_tool(tool_id)  
    print(f"External ID: {tool.external_id}")
    print(f"Tool Name: {tool.name}")
    print(f"Description: {tool.description}\n")
    print(f"Tool Keys: {tool.__dict__.keys()}\n")
    for group in tool.groups:
        print(f"Group Keys: {group.__dict__.keys()}\n")
    for technique in tool.techniques:
        print(f"Technique Keys: {technique.__dict__.keys()}\n")
        for example in technique.procedureExamples:
            print(f"Procedure Example Keys: {example.__dict__.keys()}\n")

if __name__ == "__main__":
    main()
```
### Get Groups (All)
```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    groups = mitre_data.get_groups()
    for group in groups:
        print(f"Group: {group.name}")
        print(f"Description: {group.description}")
        for technique in group.techniques:
            print(f"Technique: {technique.name}")
            for example in technique.procedureExamples:
                print(f"Procedure Example: {example.description}")

if __name__ == "__main__":
    main()
```
### Get Group (Singular)
```python
from ttpnav import MitreData

def main():
    mitre_data = MitreData()
    group_id = "G0018" # Add in your own MITRE Attack ID Here
    group = mitre_data.get_group(group_id)
    print(f"Group: {group.name}")
    print(f"Description: {group.description}")
    for technique in group.techniques:
        print(f"Technique: {technique.name}")
        for example in technique.procedureExamples:
            print(f"Procedure Example: {example.description}")

if __name__ == "__main__":
    main()
```