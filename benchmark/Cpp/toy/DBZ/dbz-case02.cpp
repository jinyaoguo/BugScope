#include <iostream>

int main() {
    double x, y;
    std::cout << "Enter two numbers: ";
    std::cin >> x >> y;
    double z = x / y;
    std::cout << "Quotient: " << z << std::endl;
    return 0;
}