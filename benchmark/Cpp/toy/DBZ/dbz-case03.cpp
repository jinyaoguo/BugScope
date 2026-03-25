#include <iostream>
#include <stdexcept>

void readInputs(double &x, double &y) {
    std::cout << "Enter two numbers (dividend and divisor): ";
    if (!(std::cin >> x >> y)) {
        throw std::runtime_error("Invalid input");
    }
}

double computeQuotient(double dividend, double divisor) {
    return dividend / divisor;
}

void printResult(double result) {
    std::cout << "Quotient: " << result << std::endl;
}

int main() {
    try {
        double x, y;
        readInputs(x, y);
        double z = computeQuotient(x, y);
        printResult(z);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}