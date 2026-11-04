// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#pragma once
#include <condition_variable>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace pail_pep_gate {
// One RPC in flight and one coalesced pending tick. Request never waits for RPC.
// The owner cancels the transport before joining and outlives the worker.
class AttestationWorker {
 public:
  AttestationWorker(std::function<void()> work,std::function<void()> cancel,
                    std::function<void(std::exception_ptr)> failure)
    :work_(std::move(work)),cancel_(std::move(cancel)),failure_(std::move(failure)),thread_([this]{Run();}){}
  ~AttestationWorker(){Stop();}
  AttestationWorker(const AttestationWorker&)=delete;
  AttestationWorker& operator=(const AttestationWorker&)=delete;
  bool Request(){
    {std::lock_guard<std::mutex> lock(mu_);if(stopping_)return false;pending_=true;}
    cv_.notify_one();return true;
  }
  void Stop(){
    std::call_once(stop_once_,[this]{
      {std::lock_guard<std::mutex> lock(mu_);stopping_=true;pending_=false;}
      cancel_();cv_.notify_all();if(thread_.joinable())thread_.join();
    });
  }
 private:
  void Run(){
    for(;;){
      {std::unique_lock<std::mutex> lock(mu_);cv_.wait(lock,[this]{return pending_||stopping_;});
       if(stopping_)return;pending_=false;}
      try{work_();}catch(...){failure_(std::current_exception());}
    }
  }
  std::function<void()> work_,cancel_;
  std::function<void(std::exception_ptr)> failure_;
  std::mutex mu_;std::condition_variable cv_;std::once_flag stop_once_;
  bool pending_{false},stopping_{false};std::thread thread_;
};
}
