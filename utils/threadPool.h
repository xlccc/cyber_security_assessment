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

class ThreadPool {
public:
    explicit ThreadPool(int numThreads);
    ~ThreadPool();

    // ģ�������ύ�ӿ�
    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;

private:
    void workerLoop(); // �����̵߳�ѭ���߼�

    std::vector<std::thread> workers;                      // �̳߳��е��߳�
    std::queue<std::function<void()>> tasks;               // �������
    std::mutex queueMutex;                                 // ������
    std::condition_variable condition;                     // ��������
    bool stop;                                             // ��־�Ƿ�ֹͣ�̳߳�
};

// ģ�������ύ�ӿڵ�ʵ��
template <class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using returnType = typename std::result_of<F(Args...)>::type;

    //�������
    auto task = std::make_shared<std::packaged_task<returnType()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<returnType> res = task->get_future();   //����future���Ա���ȡ����ֵ
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        if (stop) {
            throw std::runtime_error("[ERROR] Cannot enqueue task, ThreadPool is stopped.");
        }
        tasks.emplace([task]() { (*task)(); });
        std::cout << "[DEBUG] Task added to queue. Queue size: " << tasks.size() << ".\n";
    }
    condition.notify_one();
    return res;
}

#endif // THREADPOOL_H
