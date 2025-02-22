#include "threadPool.h"

ThreadPool::ThreadPool(int numThreads) : stop(false) {
    std::cout << "[DEBUG] Initializing ThreadPool with " << numThreads << " threads.\n";
    for (int i = 0; i < numThreads; ++i) {
        workers.emplace_back([this] { workerLoop(); });
        std::cout << "[DEBUG] Thread " << i + 1 << " created.\n";
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
    std::cout << "[DEBUG] ThreadPool destroyed. All threads joined.\n";
}

void ThreadPool::workerLoop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);

            //这个地方可以改进，循环判断条件
            condition.wait(lock, [this] { return stop || !tasks.empty(); });

            if (stop && tasks.empty()) {
                std::cout << "[DEBUG] Worker thread exiting as ThreadPool is stopped.\n";
                return;
            }

            task = std::move(tasks.front());
            tasks.pop();
            std::cout << "[DEBUG] Task retrieved from queue. Remaining tasks: " << tasks.size() << ".\n";
        }
        task();
    }
}
