// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#ifndef PAIL_CORE_COMM_IO_HPP
#define PAIL_CORE_COMM_IO_HPP
#include "pail_deploy_guard/robotops_status.hpp"
#include <rclcpp/rclcpp.hpp>
namespace pail_robotops {
// Query-time, bounded graph observation. This is not an actuation test and
// does not claim that a DDS match delivered a command to the driver.
inline std::string Endpoints(const rclcpp::Node &node,const std::string&topic,bool publishers,const rclcpp::QoS&local){
 try{
  auto endpoints=publishers?node.get_publishers_info_by_topic(topic):node.get_subscriptions_info_by_topic(topic);
  if(endpoints.size()>8)return "{\"limited\":true,\"endpoints\":[]}";
  std::string out="{\"limited\":false,\"endpoints\":[";bool first=true;
  for(const auto&e:endpoints){
   if(e.node_name().size()>256||e.node_namespace().size()>256)return "{\"limited\":true,\"endpoints\":[]}";
   const auto compatible=publishers?rclcpp::qos_check_compatible(e.qos_profile(),local):rclcpp::qos_check_compatible(local,e.qos_profile());
   const auto gid=e.endpoint_gid();std::string gidhex;const char *hex="0123456789abcdef";for(const auto b:gid){gidhex+=hex[b>>4];gidhex+=hex[b&15];}
   if(!first)out+=',';first=false;
   out+=JSON({{"node_name",e.node_name()},{"node_namespace",e.node_namespace()},{"endpoint_gid",gidhex},{"qos_compatible",compatible.compatibility==rclcpp::QoSCompatibility::Ok?"true":"unknown_or_incompatible"}});
  }return out+"]}";
 }catch(const std::exception&){return "{\"limited\":true,\"endpoints\":[]}";}
}
inline std::string Age(int64_t received,int64_t now){return received<=0||now<received?"unknown":std::to_string((now-received)/1000000);}
}
#endif
