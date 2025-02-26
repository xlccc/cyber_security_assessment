#include "threadPool.h"

ThreadPool::ThreadPool(int numThreads) : stop(false) {
    system_logger->debug("Initializing ThreadPool with {} threads.", numThreads);
    for (int i = 0; i < numThreads; ++i) {
        workers.emplace_back([this] { workerLoop(); });
        system_logger->debug("Thread {} created.", i + 1);
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread& worker : workers) {
        worker.join();
    }
    system_logger->debug("ThreadPool destroyed. All threads joined.");

}

void ThreadPool::workerLoop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);

            //这个地方可以改进，循环判断条件
            condition.wait(lock, [this] { return stop || !tasks.empty(); });

            if (stop && tasks.empty()) {
                system_logger->error("Cannot enqueue task, ThreadPool is stopped.");
                system_logger->debug("Worker thread exiting as ThreadPool is stopped.");
                return;
            }

            task = std::move(tasks.front());
            tasks.pop();
            system_logger->debug("Task retrieved from queue. Remaining tasks: {}.", tasks.size());
        }
        task();
    }
}
