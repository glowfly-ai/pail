// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#pragma once
#include <google/protobuf/message.h>
#include <google/protobuf/descriptor.h>
#include <sodium.h>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <string>
#include <algorithm>
#include <vector>
namespace pail_core_comm {
inline void U32(std::string&o,uint32_t n){for(int i=3;i>=0;--i)o.push_back(char(n>>(8*i)));}
inline void U64(std::string&o,uint64_t n){for(int i=7;i>=0;--i)o.push_back(char(n>>(8*i)));}
inline std::string Canon(const google::protobuf::Message&m,bool report=false,int depth=0){
 using F=google::protobuf::FieldDescriptor;
 if(depth>16)throw std::runtime_error("canonical depth");
 const auto*r=m.GetReflection();const auto*d=m.GetDescriptor();
 if(r->GetUnknownFields(m).field_count())throw std::runtime_error("unknown report fields");
 std::vector<const F*> fields;for(int i=0;i<d->field_count();++i)fields.push_back(d->field(i));
 std::sort(fields.begin(),fields.end(),[](const F*a,const F*b){return a->number()<b->number();});
 std::string out;
 for(const auto*f:fields){
  int n=f->number();if(report&&!(n<=11||n==16)){if(n<12||n>19)throw std::runtime_error("unclassified report field");continue;}
  if(f->is_repeated())throw std::runtime_error("report repeated field unsupported");
  std::string value;char type=0;
  switch(f->cpp_type()){
   case F::CPPTYPE_BOOL:type=1;value.push_back(r->GetBool(m,f)?1:0);break;
   case F::CPPTYPE_INT32:type=2;U32(value,uint32_t(r->GetInt32(m,f)));break;
   case F::CPPTYPE_UINT32:type=3;U32(value,r->GetUInt32(m,f));break;
   case F::CPPTYPE_INT64:type=4;U64(value,uint64_t(r->GetInt64(m,f)));break;
   case F::CPPTYPE_UINT64:type=5;U64(value,r->GetUInt64(m,f));break;
   case F::CPPTYPE_FLOAT:{type=6;float x=r->GetFloat(m,f);if(!std::isfinite(x))throw std::runtime_error("nonfinite report");if(x==0)x=0;uint32_t v;std::memcpy(&v,&x,4);U32(value,v);break;}
   case F::CPPTYPE_DOUBLE:{type=7;double x=r->GetDouble(m,f);if(!std::isfinite(x))throw std::runtime_error("nonfinite report");if(x==0)x=0;uint64_t v;std::memcpy(&v,&x,8);U64(value,v);break;}
   case F::CPPTYPE_STRING:type=f->type()==F::TYPE_BYTES?9:8;value=r->GetString(m,f);break;
   case F::CPPTYPE_MESSAGE:type=10;if(r->HasField(m,f))value=Canon(r->GetMessage(m,f),false,depth+1);break;
   case F::CPPTYPE_ENUM:{type=13;const int e=r->GetEnumValue(m,f);if(!f->enum_type()->FindValueByNumber(e))throw std::runtime_error("unknown report enum");U32(value,uint32_t(e));break;}
   default:throw std::runtime_error("unsupported report type");
  }
  U32(out,n);out.push_back(type);U64(out,value.size());out+=value;
  if(out.size()>(1u<<20))throw std::runtime_error("report too large");
 }return out;
}
inline std::string Digest(const google::protobuf::Message&m){std::string data="pail-core-report:v1";data.push_back(0);data+=Canon(m,true);unsigned char hash[32];crypto_hash_sha256(hash,reinterpret_cast<const unsigned char*>(data.data()),data.size());return std::string(reinterpret_cast<const char*>(hash),32);}
}
