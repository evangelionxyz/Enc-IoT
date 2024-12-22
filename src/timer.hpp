#pragma once
#include <chrono>
#include <iostream>

class timer
    {
    public:
        timer()
        {
            reset();
        }

        void reset()
        {
            m_Start = std::chrono::high_resolution_clock::now();
        }

        float elapsed()
        {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - m_Start).count() * 0.001f * 0.001f * 0.001f;
        }

        float elapsed_millis()
        {
            return elapsed() * 1000.0f;
        }

    private:
        std::chrono::time_point<std::chrono::high_resolution_clock> m_Start;
    };