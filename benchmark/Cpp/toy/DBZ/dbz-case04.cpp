#include <vector>
#include <iostream>
#include <stdexcept>

std::vector<int> batchDivide(int dividend, const std::vector<int> &divisors) {
    std::vector<int> results;
    results.reserve(divisors.size());
    for (int d : divisors) {
        if (d == 0)
            throw std::runtime_error("Division by zero in batchDivide()");
        results.push_back(dividend / d);
    }
    return results;
}

void printResults(int dividend, const std::vector<int> &divisors,
                  const std::vector<int> &results) {
    for (size_t i = 0; i < divisors.size(); ++i) {
        std::cout << dividend << " / " << divisors[i]
                  << " = " << results[i] << std::endl;
    }
}

int main() {
    int dividend = 100;
    std::vector<int> divisors = {2, 1, 0, 4};

    try {
        auto results = batchDivide(dividend, divisors);
        printResults(dividend, divisors, results);
    } catch (const std::exception &e) {
        std::cerr << "Error during batch division: " << e.what() << std::endl;
    }

    return 0;
}