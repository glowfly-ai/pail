// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#ifndef PAIL_DEPLOY_GUARD_ROBOTOPS_STATUS_HPP
#define PAIL_DEPLOY_GUARD_ROBOTOPS_STATUS_HPP
// Linux owner-checked, bounded, nonblocking query transport. Poll is called by
// the node's mutually exclusive ROS executor, never an authority worker thread.
// No token, signing key, configuration reload, actuation or process control API.
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <sodium.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
namespace pail_robotops {
using Fields=std::map<std::string,std::string>;
inline std::string Quote(const std::string&s){std::string o="\"";const char*h="0123456789abcdef";for(unsigned char c:s){if(c=='"'||c=='\\'){o+='\\';o+=char(c);}else if(c<32){o+="\\u00";o+=h[c>>4];o+=h[c&15];}else{o+=char(c);}}return o+'"';}
inline std::string JSON(const Fields&f){std::string o="{";bool first=true;for(const auto&kv:f){if(!first)o+=',';first=false;o+=Quote(kv.first)+":"+Quote(kv.second);}return o+"}";}
inline std::string Hash(const std::string&s){unsigned char h[crypto_hash_sha256_BYTES];crypto_hash_sha256(h,reinterpret_cast<const unsigned char*>(s.data()),s.size());char hex[65];sodium_bin2hex(hex,sizeof(hex),h,sizeof(h));return hex;}
inline std::string Decimal(double v){std::ostringstream o;o<<std::setprecision(std::numeric_limits<double>::max_digits10)<<v;return o.str();}
inline int64_t MonoNS(){return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
inline std::string ReadSmall(const std::string&path){std::ifstream f(path);std::string s;std::getline(f,s);return s;}
inline std::string StartTicks(){auto s=ReadSmall("/proc/self/stat");auto pos=s.rfind(')');if(pos==std::string::npos)return "";std::istringstream in(s.substr(pos+2));std::string word;for(int i=0;i<=19;i++){if(!(in>>word))return "";}return word;}
inline bool Hex(const std::string&s,size_t n){return s.size()==n && std::all_of(s.begin(),s.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});}
inline bool ID(const std::string&s){return !s.empty() && s.size()<=128 && s!="." && s!=".." && std::all_of(s.begin(),s.end(),[](char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.';});}
inline bool Deployment(const std::string&s){if(s.size()!=36)return false;for(size_t i=0;i<s.size();i++){if(i==8||i==13||i==18||i==23){if(s[i]!='-')return false;}else if(!Hex(s.substr(i,1),1))return false;}return true;}
inline std::string Env(const char*key){const char*v=std::getenv(key);return v?v:"";}
class StatusServer {
 struct Client{int fd;std::string input,output;size_t sent=0;int64_t deadline;};
 int listener_=-1;std::string path_;std::vector<Client>clients_;Fields identity_;ino_t inode_=0;dev_t device_=0;
 public:
 StatusServer(const std::string&path,const std::string&deployment,const std::string&robot,const std::string&component):path_(path){
  if(!Deployment(deployment)||!ID(robot)||!ID(component)||path.find("/../")!=std::string::npos||path.find("/./")!=std::string::npos||path.find("//")!=std::string::npos||path.empty()||path[0]!='/'||path.size()>=sizeof(sockaddr_un::sun_path))throw std::runtime_error("RO_STATUS: invalid identity/path");
  auto slash=path.rfind('/');auto parent=path.substr(0,slash);struct stat st{};
  // Every component must be a real directory. Do not follow an operator path
  // through symlinks, and require a private, component-owned endpoint directory.
  for(size_t end=1;end<=parent.size();end++){if(end!=parent.size()&&parent[end]!='/')continue;auto part=parent.substr(0,end);if(part.empty())continue;if(lstat(part.c_str(),&st)||!S_ISDIR(st.st_mode))throw std::runtime_error("RO_STATUS: invalid parent directory");}
  if(st.st_uid!=geteuid() || (st.st_mode&0077)!=0)throw std::runtime_error("RO_STATUS: parent must be owner-only");
  // An endpoint left behind by a process that died without its destructor (SIGKILL,
  // `docker rm -f`; measured 2026-09-23 on the TB3 rig) is reclaimed only when it is
  // a socket this euid owns and nobody answers on it. A live listener, a foreign owner
  // or a non-socket is never taken over: those are the takeover shapes this refusal
  // exists for.
  if(lstat(path.c_str(),&st)==0){
   if(!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid())throw std::runtime_error("RO_STATUS: endpoint already exists; no unlink takeover");
   int probe=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(probe<0)throw std::runtime_error("RO_STATUS: socket unavailable");
   sockaddr_un pa{};pa.sun_family=AF_UNIX;std::memcpy(pa.sun_path,path.c_str(),path.size()+1);
   const int rc=connect(probe,reinterpret_cast<sockaddr*>(&pa),sizeof(pa));const int err=errno;close(probe);
   if(rc==0||err!=ECONNREFUSED)throw std::runtime_error("RO_STATUS: endpoint in use; no takeover");
   if(unlink(path.c_str())!=0)throw std::runtime_error("RO_STATUS: stale endpoint could not be reclaimed");
   std::fprintf(stderr,"RO_STATUS: stale endpoint reclaimed (%s)\n",path.c_str());
  }else if(errno!=ENOENT)throw std::runtime_error("RO_STATUS: endpoint path unreadable");
  if(sodium_init()<0)throw std::runtime_error("RO_STATUS: crypto init unavailable");
  unsigned char nonce[16];randombytes_buf(nonce,sizeof(nonce));char instance[33];sodium_bin2hex(instance,sizeof(instance),nonce,sizeof(nonce));
  identity_={{"schema_version","1"},{"component",component},{"robot_id",robot},{"deployment_id",deployment},{"instance_id",instance},{"clock_id",instance},{"boot_id",ReadSmall("/proc/sys/kernel/random/boot_id")},{"process_pid",std::to_string(getpid())},{"process_start_ticks",StartTicks()},{"generation_algorithm","sha256:node-string-map-v1"},{"evidence_kind","local_process_self_report"},{"physical_stop_proven","false"}};
  if(identity_["boot_id"].empty()||identity_["process_start_ticks"].empty())throw std::runtime_error("RO_STATUS: process identity unavailable");
  listener_=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(listener_<0)throw std::runtime_error("RO_STATUS: socket unavailable");
  sockaddr_un addr{};addr.sun_family=AF_UNIX;std::memcpy(addr.sun_path,path.c_str(),path.size()+1);
  if(bind(listener_,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))!=0){close(listener_);listener_=-1;throw std::runtime_error("RO_STATUS: bind failed");}
  if(chmod(path.c_str(),0600)!=0||lstat(path.c_str(),&st)!=0||listen(listener_,8)!=0){close(listener_);listener_=-1;unlink(path.c_str());throw std::runtime_error("RO_STATUS: endpoint setup failed");}inode_=st.st_ino;device_=st.st_dev;
 }
 StatusServer(const StatusServer&)=delete;StatusServer&operator=(const StatusServer&)=delete;
 ~StatusServer(){for(auto&c:clients_)close(c.fd);if(listener_>=0)close(listener_);struct stat st{};if(lstat(path_.c_str(),&st)==0&&st.st_ino==inode_&&st.st_dev==device_)unlink(path_.c_str());}
 // At most eight clients and one short request per executor tick. Slow readers
 // and incomplete writers cannot block the bridge's watchdog.
 template<class Snapshot>void Poll(Snapshot snapshot){
  for(int n=0;n<8;n++){int fd=accept4(listener_,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd<0)break;ucred cred{};socklen_t len=sizeof(cred);
   if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&len)!=0||(cred.uid!=0&&cred.uid!=geteuid())||clients_.size()>=8){close(fd);continue;}
   clients_.push_back(Client{fd,"","",0,MonoNS()+250000000});
  }
  for(auto it=clients_.begin();it!=clients_.end();){bool done=MonoNS()>it->deadline;
   if(!done&&it->output.empty()){char buf[80];ssize_t n=recv(it->fd,buf,sizeof(buf),MSG_DONTWAIT);if(n==0)done=true;else if(n<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK)done=true;}else{it->input.append(buf,size_t(n));if(it->input.size()>65)done=true;else if(it->input.find('\n')!=std::string::npos){if(it->input.size()!=65||it->input.back()!='\n'||!Hex(it->input.substr(0,64),64))done=true;else{
     Fields fields=snapshot();for(const auto&kv:identity_)fields[kv.first]=kv.second;fields["nonce"]=it->input.substr(0,64);fields["sample_mono_ns"]=std::to_string(MonoNS());it->output=JSON(fields)+"\n";if(it->output.size()>16384)done=true;
   }}}}
   if(!done&&!it->output.empty()){ssize_t n=send(it->fd,it->output.data()+it->sent,it->output.size()-it->sent,MSG_DONTWAIT|MSG_NOSIGNAL);if(n>0){it->sent+=size_t(n);if(it->sent==it->output.size())done=true;}else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK)done=true;}
   if(done){close(it->fd);it=clients_.erase(it);}else ++it;
  }
 }
};
} // namespace pail_robotops
#endif
