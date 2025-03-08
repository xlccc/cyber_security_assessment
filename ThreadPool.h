#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <iostream>
#include "log/log.h"

class ThreadPool {
public:
    explicit ThreadPool(int numThreads);
    ~ThreadPool();

    // 模板任务提交接口
    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;

private:
    void workerLoop(); // 工作线程的循环逻辑

    std::vector<std::thread> workers;                      // 线程池中的线程
    std::queue<std::function<void()>> tasks;               // 任务队列
    std::mutex queueMutex;                                 // 队列锁
    std::condition_variable condition;                     // 条件变量
    bool stop;                                             // 标志是否停止线程池
};

// 模板任务提交接口的实现
template <class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using returnType = typename std::result_of<F(Args...)>::type;

    //打包任务
    auto task = std::make_shared<std::packaged_task<returnType()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<returnType> res = task->get_future();   //创建future，以备提取返回值
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        if (stop) {
            throw std::runtime_error("[ERROR] Cannot enqueue task, ThreadPool is stopped.");
        }
        tasks.emplace([task]() { (*task)(); });
        system_logger->debug("Task added to queue. Queue size: {}.", tasks.size());
    }
    condition.notify_one();
    return res;
}

#endif // THREADPOOL_H