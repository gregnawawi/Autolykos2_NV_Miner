// aukos.cu

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/easylogging++.h"
#include "../include/jsmn.h"
#include "../include/mini.h"
#include "../include/prehash.h"
#include "../include/processing.h"
#include "../include/reduction.h"
#include "../include/request.h"
#include "../include/httpapi.h"
#include "../include/queue.h"
#include "../include/cpuAukos.h"
#include <ctype.h>
#include <cuda.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>
#include <random>

#ifdef _WIN32
#include <io.h>
#define R_OK 4       
#define W_OK 2       
#define F_OK 0       
#define access _access
#else
#include <unistd.h>
#endif

INITIALIZE_EASYLOGGINGPP

using namespace std::chrono;

std::atomic<int> end_jobs(0);

void SenderThread(info_t * info, BlockQueue<rShare>* shQueue)
{
	el::Helpers::setThreadName("sender thread");
    while(true)
    {
		rShare share = shQueue->get();
		PostPuzzleSolution(info->to, (uint8_t*)&share.nonce);
    }
}

void rThread(const int totalGPUCards, int deviceId, info_t * info, std::vector<double>* hashrates, std::vector<int>* tstamps, BlockQueue<rShare>* shQueue)
{
	AutolykosAlg solVerifier;
    CUDA_CALL(cudaSetDevice(deviceId));
    cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
    char threadName[20];
    sprintf(threadName, "G %i wrkr", deviceId);
    el::Helpers::setThreadName(threadName);    

    state_t state = STATE_KEYGEN;
    json_t request(0, REQ_LEN);

    // hash context
    // (212 + 4) bytes
	//ctx_t ctx_h;

    uint8_t bound_h[NUM_SIZE_8];
    uint8_t mes_h[NUM_SIZE_8];
    uint8_t nonce[NONCE_SIZE_8];

    char to[MAX_URL_SIZE];
 
    uint_t blockId = 0;
    milliseconds start; 
    
    info->info_mutex.lock();

    memcpy(mes_h, info->mes, NUM_SIZE_8);
    memcpy(bound_h, info->bound, NUM_SIZE_8);
    memcpy(to, info->to, MAX_URL_SIZE * sizeof(char));
    
    info->info_mutex.unlock();

    size_t freeMem;
    size_t totalMem;

    CUDA_CALL(cudaMemGetInfo(&freeMem, &totalMem));
    
    if (freeMem < MIN_FREE_MEMORY)
    {
        return;
    }

    uint32_t * height_d;
    CUDA_CALL(cudaMalloc(&height_d, HEIGHT_SIZE));

    uint32_t * data_d;
    CUDA_CALL(cudaMalloc(&data_d, NUM_SIZE_8 + sizeof(ctx_t) ) );

    
    uint32_t* BHashes;
    CUDA_CALL(cudaMalloc(&BHashes, (NUM_SIZE_8)*THREADS_PER_ITER) );

    uint32_t * hashes_d; 
    CUDA_CALL(cudaMalloc(&hashes_d, (uint32_t)N_LEN * NUM_SIZE_8) );

    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc(&indices_d, MAX_SOLS*sizeof(uint32_t)) );

    uint32_t indices_h[MAX_SOLS];
    
    uint32_t * count_d;

    CUDA_CALL(cudaMalloc(&count_d,sizeof(uint32_t)) );

    CUDA_CALL(cudaMemset(count_d,0,sizeof(uint32_t)));

    
    CUDA_CALL(cudaMemset(
        indices_d, 0, sizeof(uint32_t)*MAX_SOLS
    ));

    uint64_t base = 0;
    uint64_t EndNonce = 0;
    uint32_t height = 0;

	
    int cntCycles = 0;
    int NCycles = 50;

    while (info->blockId.load() == 0) {}

    start = duration_cast<milliseconds>(system_clock::now().time_since_epoch());

    do
    {
        ++cntCycles;
        if (!(cntCycles % NCycles))
        {
            milliseconds timediff
                = duration_cast<milliseconds>(
                    system_clock::now().time_since_epoch()
                ) - start;
            

            (*hashrates)[deviceId] = (double)NONCES_PER_ITER * (double)NCycles
                / ((double)1000 * timediff.count());
             
	    
            start = duration_cast<milliseconds>(
                system_clock::now().time_since_epoch()
            );

            (*tstamps)[deviceId] = start.count();
        }
    
        if (state == STATE_KEYGEN)
        {
            while (info->blockId.load() == blockId) 
	    {
	        std::this_thread::sleep_for(std::chrono::milliseconds(10));
	    }

            state = STATE_CONTINUE;
        }

		while (!info->doJob)
		{
		        std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

        uint_t controlId = info->blockId.load();
        
        if (blockId != controlId)
        {
            info->info_mutex.lock();

            memcpy(mes_h, info->mes, NUM_SIZE_8);
            memcpy(bound_h, info->bound, NUM_SIZE_8);


			memcpy(&EndNonce, info->extraNonceEnd, NONCE_SIZE_8);
			memcpy(&base, info->extraNonceStart, NONCE_SIZE_8);
			uint64_t nonceChunk = 1 + (EndNonce - base) / totalGPUCards;
			base = *((uint64_t *)info->extraNonceStart) + deviceId * nonceChunk;
            EndNonce = base + nonceChunk;
                        
            memcpy(&height,info->Hblock, HEIGHT_SIZE);

            info->info_mutex.unlock();

            blockId = controlId;

            CUDA_CALL(cudaMemcpy(
                ((uint8_t *)data_d), mes_h, NUM_SIZE_8,
                cudaMemcpyHostToDevice
            ));

            Prehash(hashes_d,height);
            cpyBSymbol(bound_h);
            
            CUDA_CALL(cudaDeviceSynchronize());
            state = STATE_CONTINUE;
        }

        BlockMiniStep1<<<1 + (THREADS_PER_ITER - 1) / (BLOCK_DIM*4), BLOCK_DIM>>>(data_d, base, hashes_d, BHashes);
        BlockMiniStep2<<<1 + (THREADS_PER_ITER - 1) / BLOCK_DIM, BLOCK_DIM>>>(data_d, base,height, hashes_d, indices_d , count_d,BHashes);
        if (blockId != info->blockId.load()) { continue;}

		CUDA_CALL(cudaMemcpy(
            indices_h, indices_d, MAX_SOLS*sizeof(uint32_t),
            cudaMemcpyDeviceToHost
        ));
		
        if (indices_h[0])
        {
            
            
			int i = 0;
			while (indices_h[i] && (i < 16/*MAX_SOLS*/)  )
			{
				if(!info->stratumMode && i != 0)
				{
					break;
				}

				*((uint64_t *)nonce) = base + indices_h[i] - 1;
				uint64_t endNonceT;
				memcpy(&endNonceT , info->extraNonceEnd , sizeof(uint64_t));
				if ( (*((uint64_t *)nonce)) <= endNonceT )
				{
					bool checksol = solVerifier.RunAlg(info->mes,nonce,info->bound,info->Hblock);
					if (checksol)
					{
						rShare share(*((uint64_t *)nonce));
						shQueue->put(share);
						if (!info->stratumMode)
						{
							state = STATE_KEYGEN;
							break;
						}
					}
                }
		i++;
	}

            memset(indices_h,0,MAX_SOLS*sizeof(uint32_t));
            CUDA_CALL(cudaMemset(
                indices_d, 0, MAX_SOLS*sizeof(uint32_t)
            ));
  			CUDA_CALL(cudaMemset(count_d,0,sizeof(uint32_t)));
        }
       base += NONCES_PER_ITER;
       if (base > EndNonce)
       {
           state = STATE_KEYGEN;
           end_jobs.fetch_add(1, std::memory_order_relaxed);
       }

    }
    while (1);
}


int main(int argc, char ** argv)
{
    START_EASYLOGGINGPP(argc, argv);

    el::Loggers::reconfigureAllLoggers(
        el::ConfigurationType::Format, "%datetime %level [%thread] %msg"
    );

    el::Helpers::setThreadName("main thread");

    int deviceCount;
    int status = EXIT_SUCCESS;

    if (cudaGetDeviceCount(&deviceCount) != cudaSuccess)
    {
        return EXIT_FAILURE;
    }

    char confName[14] = "./.aux";
    char * fileName = (argc == 1)? confName: argv[1];
    char from[MAX_URL_SIZE];
    info_t info;
    info.blockId = 0;
    info.keepPrehash = 0;
    
    BlockQueue<rShare> solQueue;

    if (access(fileName, F_OK) == -1)
    {
        return EXIT_FAILURE;
    }

    status = ReadConfig(
        fileName, from, info.to, info.endJob
     );

    if (status == EXIT_FAILURE) { return EXIT_FAILURE; }

    json_t request(0, REQ_LEN);

    PERSISTENT_CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), CURLE_OK);
    
    std::vector<std::thread> allDevice(deviceCount);
    std::vector<double> hashrates(deviceCount);
    std::vector<int> lastTimestamps(deviceCount);
    std::vector<int> timestamps(deviceCount);
	
    std::vector<std::pair<int,int>> devinfos(deviceCount);
    for (int i = 0; i < deviceCount; ++i)
    {
        cudaDeviceProp props;
        if(cudaGetDeviceProperties(&props, i) == cudaSuccess)
        {
            devinfos[i] = std::make_pair(props.pciBusID, props.pciDeviceID);
        }
        allDevice[i] = std::thread(rThread,deviceCount, i, &info, &hashrates, &timestamps, &solQueue);
        hashrates[i] = 0;
        lastTimestamps[i] = 1;
        timestamps[i] = 0;
    }

    status = EXIT_FAILURE;
    while(status != EXIT_SUCCESS)
    {
        status = GetLatestBlock(from, &request, &info, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
    }
    std::thread solSender(SenderThread, &info, &solQueue);
    std::thread httpApi = std::thread(HttpApiThread,&hashrates,&devinfos);    

    uint_t curlcnt = 0;
    const uint_t curltimes = 1000;

    milliseconds ms = milliseconds::zero();


while (1)
    {
        milliseconds start = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        );
	
        status = GetLatestBlock(from, &request, &info, 0);
        
        if (status != EXIT_SUCCESS) { LOG(INFO) << "Getting error"; }

        ms += duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ) - start;

        ++curlcnt;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        int completeMine = end_jobs.load();
		if (completeMine >= deviceCount)
		{
			end_jobs.store(0);
			JobCompleted(info.endJob);
		}
    }    

    return EXIT_SUCCESS;
}

// aukos.cu
