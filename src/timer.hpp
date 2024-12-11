#pragma once
#include <chrono>
#include <iostream>

class timer
{
public:
    timer(){
        start = std::chrono::high_resolution_clock::now();
    }
    ~timer(){
        end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        std::cout << "Elapsed time: " << elapsed.count() << " seconds\n";
    }

private:
    std::chrono::_V2::system_clock::time_point start, end;
};