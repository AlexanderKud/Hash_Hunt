#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <string>

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "util/util.h"

using namespace std;

const int cpuCores = std::thread::hardware_concurrency();
const char hex_chars[] = "0123456789abcdef";

std::string bytesToHexString(const unsigned char* data) {
    
    std::string result;
    result.reserve(20 * 2); // Pre-allocate memory for efficiency

    unsigned char byte;
    for (size_t i = 0; i < 20; ++i) {
        byte = data[i];
        result += hex_chars[byte >> 4];   // High nibble
        result += hex_chars[byte & 0x0F]; // Low nibble
    }
    
    return result;
}

auto main() -> int {

    Secp256K1* secp256k1 = new Secp256K1(); secp256k1->Init();
    
    Int pk; pk.SetInt32(1);
    uint64_t mult = 2;
    vector<Int> S_table;
    for (int i = 0; i < 256; i++)
    {
        S_table.push_back(pk);
        pk.Mult(mult);
    }
    print_time(); cout << "S_table generated" << endl;

    uint64_t range_start, range_end;
    string temp, target_hash;
    ifstream inFile("settings.txt");
    getline(inFile, temp); range_end = std::stoull(temp);
    getline(inFile, temp); target_hash = trim(temp);
    inFile.close();
    range_start = range_end - (uint64_t)1;
    
    print_time(); cout << "Range Start : " << range_start << " bits" << endl;
    print_time(); cout << "Range End   : " << range_end << " bits" << endl;
    print_time(); cout << "Target Hash : " << target_hash << endl;
    
    auto chrono_start = std::chrono::high_resolution_clock::now();
    
    auto hash_hunt = [&]() {
        
        Int start, cores, width, r;
        start.Set(&S_table[range_start]);
        cores.SetInt32(cpuCores);
        width.Set(&start);
        width.Div(&cores, &r);
        
        vector<Int> start_points;
        for (int i = 0; i < cpuCores; i++) {
            start_points.push_back(start);
            start.Add(&width);
        }
        
        auto process_range = [&](int ThreadId, Int start_point, Int width_set) {
            
            Int start, width, fin;
            start.Set(&start_point);
            width.Set(&width_set);
            fin.Add(&start, &width);
            unsigned char hash160[20];
            string ripemd160;
            Point P = secp256k1->ComputePublicKey(&start);

            while (start.IsLower(&fin)) {

                secp256k1->GetHash160(0, true, P, hash160);
                ripemd160 = bytesToHexString(hash160);

                if (ripemd160 == target_hash) {
                    print_time(); cout << "Private key : " << start.GetBase10() << endl;
                    ofstream outFile;
                    outFile.open("found.txt", ios::app);
                    outFile << start.GetBase10() << '\n';
                    outFile.close();
                    print_elapsed_time(chrono_start);
                    exit(0);
                }

                P = secp256k1->AddPoints(P, secp256k1->G);
                start.AddOne();
            }
            
        };
        
        std::thread threads[cpuCores];
        
        for (int i = 0; i < cpuCores; i++) {
            threads[i] = std::thread(process_range, i, start_points[i], width);
        }
        
        for (int i = 0; i < cpuCores; i++) {
            threads[i].join();
        }
    };
    
    print_time(); cout << "Hash Hunt in progress..." << endl;
    
    std::thread thread(hash_hunt);
    
    thread.join();
}
