# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""core-comm-v1 report digest/receipt validation. No authority is minted here."""
import hashlib
import math
import struct
import uuid

def _field(f,value,depth):
    from google.protobuf.descriptor import FieldDescriptor as F
    if f.type==F.TYPE_BOOL:return 1,bytes([int(value)])
    if f.type in (F.TYPE_INT32,F.TYPE_SINT32,F.TYPE_SFIXED32):return 2,struct.pack('>i',value)
    if f.type in (F.TYPE_UINT32,F.TYPE_FIXED32):return 3,struct.pack('>I',value)
    if f.type in (F.TYPE_INT64,F.TYPE_SINT64,F.TYPE_SFIXED64):return 4,struct.pack('>q',value)
    if f.type in (F.TYPE_UINT64,F.TYPE_FIXED64):return 5,struct.pack('>Q',value)
    if f.type in (F.TYPE_FLOAT,F.TYPE_DOUBLE):
        if not math.isfinite(value):raise ValueError('NONFINITE_REPORT')
        return (6,struct.pack('>f',value if value else 0.)) if f.type==F.TYPE_FLOAT else (7,struct.pack('>d',value if value else 0.))
    if f.type==F.TYPE_STRING:return 8,value.encode('utf8')
    if f.type==F.TYPE_BYTES:return 9,value
    if f.type==F.TYPE_MESSAGE:return 10,_canonical(value,False,depth+1)
    if f.type==F.TYPE_ENUM:
        if value not in f.enum_type.values_by_number:raise ValueError('UNKNOWN_REPORT_ENUM')
        return 13,struct.pack('>i',value)
    raise ValueError('UNSUPPORTED_REPORT_FIELD')

def _canonical(message,root,depth=0,include=None,exclude=()):
    if depth>16 or message.ByteSize()>1<<20:raise ValueError('REPORT_BOUND')
    clone=type(message)();clone.CopyFrom(message);clone.DiscardUnknownFields()
    if clone.SerializeToString(deterministic=True)!=message.SerializeToString(deterministic=True):raise ValueError('UNKNOWN_REPORT_FIELD')
    out=bytearray()
    for f in sorted(message.DESCRIPTOR.fields,key=lambda f:f.number):
        if include is not None and f.number not in include:
            if f.number not in exclude:raise ValueError('UNCLASSIFIED_OPERATION_FIELD')
            continue
        if root and f.number not in (*range(1,12),16):
            if f.number not in (12,13,14,15,17,18,19):raise ValueError('UNCLASSIFIED_REPORT_FIELD')
            continue
        if f.is_repeated:
            values=getattr(message,f.name)
            if f.type==f.TYPE_MESSAGE and f.message_type.GetOptions().map_entry:
                key_field=f.message_type.fields_by_name['key'];value_field=f.message_type.fields_by_name['value'];entries=[];used=8
                for k,v in values.items():
                    kk,kb=_field(key_field,k,depth);vk,vb=_field(value_field,v,depth)
                    entry=struct.pack('>BQ',kk,len(kb))+kb+struct.pack('>BQ',vk,len(vb))+vb;used+=len(entry)
                    if used>1<<20:raise ValueError('REPORT_BOUND')
                    entries.append(entry)
                kind=12;value=struct.pack('>Q',len(entries))+b''.join(sorted(entries))
            else:
                kind=11;parts=[struct.pack('>Q',len(values))];used=8
                for v in values:
                    k,b=_field(f,v,depth);piece=struct.pack('>BQ',k,len(b))+b;used+=len(piece)
                    if used>1<<20:raise ValueError('REPORT_BOUND')
                    parts.append(piece)
                value=b''.join(parts)
        elif f.type==f.TYPE_MESSAGE and not message.HasField(f.name):kind,value=10,b''
        else:kind,value=_field(f,getattr(message,f.name),depth)
        out.extend(struct.pack('>IBQ',f.number,kind,len(value)));out.extend(value)
    if len(out)>1<<20:raise ValueError('REPORT_BOUND')
    return bytes(out)

def report_digest(message):return hashlib.sha256(b'pail-core-report:v1\0'+_canonical(message,True)).digest()

def prepare_report(message,event_id=None):
    if not hasattr(message,'receipt_contract_version'):raise ValueError('CORE_CONTRACT_SCHEMA_UNAVAILABLE')
    message.report_id=event_id or uuid.uuid4().hex
    message.receipt_contract_version=1
    message.report_digest=report_digest(message)
    return message

def accepted_report(req,response):
    if response is None or not response.accepted:return False
    if not req.receipt_contract_version:return True
    if not response.HasField('receipt'):return False
    r=response.receipt
    if r.contract_version!=1 or r.report_id!=req.report_id or r.report_digest!=req.report_digest or r.robot_id!=req.robot_id or not r.receiver_instance_id:return False
    # Wire enum numbers fixed by token_service.proto core-comm-v1.
    valid_disposition=r.disposition in (1,2) or (req.step_complete and not req.fatal and r.storage==3 and r.effect_scope==2 and r.disposition==3)
    if not valid_disposition:return False
    if req.fatal:return r.storage==4 and r.effect==3 and r.effect_scope==3 and bool(r.journal_record_ref)
    if req.step_complete:return r.storage in (3,4) and r.effect==3 and r.effect_scope in (2,3)
    return r.storage in (2,3,4) and r.effect in (1,3)
