// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#include "pail_deploy_guard/robotops_status.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>
#include <thread>
int connect_to(const std::string&path){int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0);sockaddr_un a{};a.sun_family=AF_UNIX;std::strcpy(a.sun_path,path.c_str());int rc=connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a));if(rc!=0&&errno!=EINPROGRESS){close(fd);return -1;}return fd;}
int main(){
 char tmp[]="/tmp/pail-status-unit-XXXXXX";char*dir=mkdtemp(tmp);assert(dir);std::string root=dir,path=root+"/status.sock";
 assert(pail_robotops::Quote("\"\n\\")=="\"\\\"\\u000a\\\\\"");assert(pail_robotops::Hash("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 int calls=0;auto sample=[&](){++calls;return pail_robotops::Fields{{"state","HOLD"},{"output_seq","0"}};};
 {
  pail_robotops::StatusServer server(path,"5e8b24a0-2319-4a53-b5cf-a03afc977301","robot-01","fixture");
  bool refused=false;try{pail_robotops::StatusServer takeover(path,"5e8b24a0-2319-4a53-b5cf-a03afc977301","robot-01","fixture");}catch(...){refused=true;}assert(refused);
  int fd=connect_to(path);assert(fd>=0);std::string nonce(64,'a');send(fd,(nonce+"\n").data(),65,MSG_NOSIGNAL);
  std::string reply;for(int i=0;i<100&&reply.find('\n')==std::string::npos;i++){server.Poll(sample);char buf[4096];auto n=recv(fd,buf,sizeof(buf),MSG_DONTWAIT);if(n>0)reply.append(buf,size_t(n));std::this_thread::sleep_for(std::chrono::milliseconds(1));}
  close(fd);assert(calls==1);assert(reply.find("\"nonce\":\""+nonce+"\"")!=std::string::npos);assert(reply.find("\"physical_stop_proven\":\"false\"")!=std::string::npos);
  fd=connect_to(path);send(fd,"apply\n",6,MSG_NOSIGNAL);for(int i=0;i<5;i++)server.Poll(sample);close(fd);assert(calls==1);
  std::vector<int> slow;for(int i=0;i<16;i++)slow.push_back(connect_to(path));auto before=pail_robotops::MonoNS();for(int i=0;i<20;i++)server.Poll(sample);assert(pail_robotops::MonoNS()-before<100000000);assert(calls==1);for(int x:slow)if(x>=0)close(x);
 }
 struct stat st{};assert(lstat(path.c_str(),&st)!=0);
 // A stale endpoint (bound, then the process died without its destructor) is reclaimed:
 // same euid, a socket, nobody listening. The server comes up and answers on it.
 {
  int stale=socket(AF_UNIX,SOCK_STREAM,0);sockaddr_un a{};a.sun_family=AF_UNIX;std::strcpy(a.sun_path,path.c_str());assert(bind(stale,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);close(stale);
  assert(lstat(path.c_str(),&st)==0&&S_ISSOCK(st.st_mode));
  pail_robotops::StatusServer reclaimed(path,"5e8b24a0-2319-4a53-b5cf-a03afc977301","robot-01","fixture");
  int fd=connect_to(path);assert(fd>=0);std::string nonce(64,'b');send(fd,(nonce+"\n").data(),65,MSG_NOSIGNAL);
  std::string reply;for(int i=0;i<100&&reply.find('\n')==std::string::npos;i++){reclaimed.Poll(sample);char buf[4096];auto n=recv(fd,buf,sizeof(buf),MSG_DONTWAIT);if(n>0)reply.append(buf,size_t(n));std::this_thread::sleep_for(std::chrono::milliseconds(2));}
  close(fd);assert(reply.find("\"nonce\":\""+nonce+"\"")!=std::string::npos);
  // A live endpoint is still never taken over (the first block above proved the
  // same while a server was alive; this one is the reclaimed server).
  bool refused=false;try{pail_robotops::StatusServer takeover(path,"5e8b24a0-2319-4a53-b5cf-a03afc977301","robot-01","fixture");}catch(const std::exception&e){refused=std::string(e.what()).find("in use")!=std::string::npos;}assert(refused);
 }
 assert(lstat(path.c_str(),&st)!=0);
 // A regular file at the endpoint path is not a stale socket: refused, left in place.
 {
  FILE*f=fopen(path.c_str(),"w");assert(f);fputs("x",f);fclose(f);
  bool refused=false;try{pail_robotops::StatusServer bad(path,"5e8b24a0-2319-4a53-b5cf-a03afc977301","robot-01","fixture");}catch(const std::exception&e){refused=std::string(e.what()).find("no unlink takeover")!=std::string::npos;}assert(refused);
  assert(lstat(path.c_str(),&st)==0&&S_ISREG(st.st_mode));unlink(path.c_str());
 }
 chmod(root.c_str(),0755);bool refused=false;try{pail_robotops::StatusServer bad(path,"5e8b24a0-2319-4a53-b5cf-a03afc977301","robot-01","fixture");}catch(...){refused=true;}assert(refused);rmdir(root.c_str());std::cout<<"PASS status transport: nonce, no takeover, malformed refusal, bounded slow clients, private parent\n";
}
