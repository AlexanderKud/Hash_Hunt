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
const int POINTS_BATCH_SIZE = 1024;
const char hex_chars[] = "0123456789abcdef";

std::string bytesToHexString(const unsigned char* data) {
    
    std::string result;
    result.reserve(20 * 2); // Pre-allocate memory

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
        
        Int start, cores, keysPerThread, r, batch_size, nbBatch;
        start.Set(&S_table[range_start]);
        cores.SetInt32(cpuCores);
        keysPerThread.Set(&start);
        keysPerThread.Div(&cores, &r);
        batch_size.SetInt32(POINTS_BATCH_SIZE);
        
        vector<Int> start_points;
        for (int i = 0; i < cpuCores; i++) {
            start_points.push_back(start);
            start.Add(&keysPerThread);
        }

        Point addPoints[POINTS_BATCH_SIZE];
        Point batch_Add = secp256k1->DoubleDirect(secp256k1->G);
        addPoints[0] = secp256k1->G;
        addPoints[1] = batch_Add;
        for (int i = 2; i < POINTS_BATCH_SIZE; i++)
        {
            batch_Add = secp256k1->AddPoints(batch_Add, secp256k1->G);
            addPoints[i] = batch_Add;
        }
        
        nbBatch.Set(&keysPerThread);
        nbBatch.Div(&batch_size, &r); 
        
        auto process_range = [&](int ThreadId, Int start_point, Int batch_count, Int batchSize) {
            
            Int start;
            start.Set(&start_point);
            unsigned char hash160[20];
            string ripemd160;

            IntGroup modGroup(POINTS_BATCH_SIZE);
            Int deltaX[POINTS_BATCH_SIZE];
            modGroup.Set(deltaX);
            Int pointBatchX[POINTS_BATCH_SIZE];
            Int pointBatchY[POINTS_BATCH_SIZE];
            Int deltaY, slope;
                      
            Point startPoint = secp256k1->ComputePublicKey(&start);
            startPoint = secp256k1->SubtractPoints(startPoint, secp256k1->G);
            Point P;
            Int priv_keys[POINTS_BATCH_SIZE];
            Int priv;
            
            while (!batch_count.IsZero()) {

                priv.Set(&start);
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    priv_keys[i] = priv;
                    priv.AddOne();
                }


                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    deltaX[i].ModSub(&startPoint.x, &addPoints[i].x);
                }
    
                modGroup.ModInv();
                
                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {
                    
                    deltaY.ModSub(&startPoint.y, &addPoints[i].y);
                    slope.ModMulK1(&deltaY, &deltaX[i]);

                    pointBatchX[i].ModSquareK1(&slope);
                    pointBatchX[i].ModSub(&pointBatchX[i], &startPoint.x);
                    pointBatchX[i].ModSub(&pointBatchX[i], &addPoints[i].x);

                    pointBatchY[i].ModSub(&startPoint.x, &pointBatchX[i]);
                    pointBatchY[i].ModMulK1(&slope, &pointBatchY[i]);
                    pointBatchY[i].ModSub(&pointBatchY[i], &startPoint.y);

                }
                

                for (int i = 0; i < POINTS_BATCH_SIZE; i++) {

                    P.x.Set(&pointBatchX[i]);
                    P.y.Set(&pointBatchY[i]);
                    secp256k1->GetHash160(0, true, P, hash160);
                    ripemd160 = bytesToHexString(hash160);

                    if (ripemd160 == target_hash) {
                        print_time(); cout << "Private key : " << priv_keys[i].GetBase10() << endl;
                        ofstream outFile;
                        outFile.open("found.txt", ios::app);
                        outFile << priv_keys[i].GetBase10() << '\n';
                        outFile.close();
                        print_elapsed_time(chrono_start);
                        exit(0);
                    }
                }
                
                startPoint.x.Set(&pointBatchX[POINTS_BATCH_SIZE - 1]);
                startPoint.y.Set(&pointBatchY[POINTS_BATCH_SIZE - 1]);
                nbBatch.SubOne();
                start.Add(&batchSize);
            }
            
        };
        
        std::thread threads[cpuCores];
        
        for (int i = 0; i < cpuCores; i++) {
            threads[i] = std::thread(process_range, i, start_points[i], nbBatch, batch_size);
        }
        
        for (int i = 0; i < cpuCores; i++) {
            threads[i].join();
        }
    };
    
    print_time(); cout << "Hash Hunt in progress..." << endl;
    
    std::thread thread(hash_hunt);
    
    thread.join();
}
