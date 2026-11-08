"""Small fail-closed evaluator for the checked-in JSON Schema subset.
No network references or third-party runtime dependencies. Full Draft 2020-12
conformance is independently checked by jsonschema in development/CI tests.
"""
import json
from pathlib import Path
import re

TYPES={'object':dict,'array':list,'string':str,'boolean':bool,'integer':int,'null':type(None)}
SUPPORTED={'$schema','$id','title','description','$ref','type','properties','required','additionalProperties','items','enum','const','pattern','minimum','minItems'}

def validate_instance(value, schema, schema_root):
    if set(schema)-SUPPORTED:raise ValueError('Unsupported runtime schema keyword')
    if '$ref' in schema:
        name=schema['$ref']
        if not re.fullmatch(r'[a-z-]+\.schema\.json',name):raise ValueError('External schema reference forbidden')
        validate_instance(value,json.loads((Path(schema_root)/name).read_text()),schema_root)
        return
    types=schema.get('type',[])
    if isinstance(types,str):types=[types]
    if types and not any(type(value) is TYPES[t] for t in types):raise ValueError('Schema type mismatch')
    if 'enum' in schema and value not in schema['enum']:raise ValueError('Schema enum mismatch')
    if 'const' in schema and (type(value) is not type(schema['const']) or value!=schema['const']):raise ValueError('Schema constant mismatch')
    if isinstance(value,dict):
        if set(schema.get('required',[]))-set(value):raise ValueError('Schema required fields missing')
        properties=schema.get('properties',{})
        if schema.get('additionalProperties') is False and set(value)-set(properties):raise ValueError('Schema additional fields forbidden')
        for key,child in properties.items():
            if key in value:validate_instance(value[key],child,schema_root)
    if isinstance(value,list):
        if len(value)<schema.get('minItems',0):raise ValueError('Schema array too short')
        if 'items' in schema:
            for item in value:validate_instance(item,schema['items'],schema_root)
    if isinstance(value,str) and 'pattern' in schema and not re.search(schema['pattern'],value):raise ValueError('Schema string pattern mismatch')
    if type(value) is int and 'minimum' in schema and value<schema['minimum']:raise ValueError('Schema below minimum')
