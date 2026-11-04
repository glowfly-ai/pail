// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#include "pail_pep_gate/attestation_worker.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
int main(){
 std::mutex mu;std::condition_variable cv;bool release=false;std::atomic<int> calls{0},failures{0};
 pail_pep_gate::AttestationWorker worker([&]{
   calls++;cv.notify_all();std::unique_lock<std::mutex> l(mu);cv.wait(l,[&]{return release;});
 },[&]{std::lock_guard<std::mutex> l(mu);release=true;cv.notify_all();},[&](std::exception_ptr){failures++;});
 worker.Request();
 {std::unique_lock<std::mutex> l(mu);if(!cv.wait_for(l,std::chrono::seconds(1),[&]{return calls.load()==1;}))return 1;}
 // A hung callback does not block these requests. All ticks coalesce into one.
 for(int i=0;i<1000;i++)if(!worker.Request())return 2;
 if(calls.load()!=1)return 3;
 {std::lock_guard<std::mutex> l(mu);release=true;}cv.notify_all();
 {std::unique_lock<std::mutex> l(mu);if(!cv.wait_for(l,std::chrono::seconds(1),[&]{return calls.load()==2;}))return 4;}
 worker.Stop();worker.Stop();if(worker.Request()||calls.load()!=2||failures.load())return 5;
 std::puts("PASS: nonblocking ticks, one pending request, cancellation and idempotent shutdown");
}
